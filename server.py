"""MCP server for read-only queries against the Oracle SQL production-view database.

Connection credentials are read from environment variables:
    DB_SCHEME_PROD_VIEW    -> Oracle service name (or SID)
    DB_HOST_PROD_VIEW      -> host, optionally "host:port" (default port 1521)
    DB_USER_PROD_VIEW      -> user
    DB_PASSWORD_PROD_VIEW  -> password
    DB_SCHEMA              -> schema owning the objects (e.g. CL). If empty,
                              queries run unqualified and metadata comes from
                              user_tables / user_views / user_tab_columns.

Runs over Streamable HTTP on MCP_HOST:MCP_PORT so it can be exposed via cloudflared.
MCP_PORT is required (no default); MCP_HOST defaults to 0.0.0.0.

All query tools are paginated so big tables never dump everything at once.
"""

import os
import re
import hmac
import math
import logging
import contextlib
from logging.handlers import RotatingFileHandler

import oracledb
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

import oauth

# Process title -> findable in htop/ps and killable with `pkill consulta_db_mcp`.
PROC_NAME = "consulta_db_mcp"
try:
    import setproctitle
    setproctitle.setproctitle(PROC_NAME)
except Exception:
    pass

HOST = os.environ.get("MCP_HOST", "0.0.0.0").strip() or "0.0.0.0"
_PORT_RAW = os.environ.get("MCP_PORT", "").strip()
if not _PORT_RAW:
    raise SystemExit("MCP_PORT is required (set it in .env)")
PORT = int(_PORT_RAW)

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000

# Schema that owns the objects. Set via DB_SCHEMA. If empty/None, queries are
# unqualified and metadata is read from user_* dictionary views instead of all_*.
SCHEMA: str | None = os.environ.get("DB_SCHEMA", "").strip().upper() or None
SCHEMA_PREFIX = f"{SCHEMA}." if SCHEMA else ""


def _qualify(name: str) -> str:
    """Prepend SCHEMA. to a bare table name when a schema is configured."""
    return f"{SCHEMA}.{name}" if SCHEMA else name

# ---- logging --------------------------------------------------------------
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "consulta_db.log")

log = logging.getLogger("consulta_db")
if not log.handlers:
    log.setLevel(logging.INFO)
    _fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    _fh = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    _fh.setFormatter(_fmt)
    _sh = logging.StreamHandler()
    _sh.setFormatter(_fmt)
    log.addHandler(_fh)
    log.addHandler(_sh)


def _one_line(sql: str, limit: int = 1000) -> str:
    """Collapse a SQL string to one line for logging (no row data here, just the query)."""
    s = " ".join(sql.split())
    return s if len(s) <= limit else s[:limit] + "...[truncated]"
# ---------------------------------------------------------------------------

# ---- documentacion del esquema (carpeta ./docs) ---------------------------
# `docs/` tiene un Markdown por objeto del esquema configurado — para que sirve, campos,
# tipos, llaves, uniones — mas `docs/INDEX.md` (catalogo). Lo genera/actualiza una
# sesion de Claude siguiendo `PROMPT_DOCUMENTAR.md` (no es tiempo real). Estas tools
# dejan que el modelo lo consulte sin tocar Oracle.
DOCS_DIR = os.environ.get(
    "DB_DOCS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs"),
)
DOCS_DIR = os.path.abspath(DOCS_DIR)


def _doc_path(name: str) -> str:
    """Ruta del .md de un objeto. Acepta 'SCHEMA.X', 'x', 'SCHEMA.X.md', o 'INDEX'."""
    base = os.path.basename(name.strip()).strip().strip('"')
    if base.lower().endswith(".md"):
        base = base[:-3]
    if base.upper() in ("INDEX", "INDICE"):
        return os.path.join(DOCS_DIR, "INDEX.md")
    short = base.split(".", 1)[-1].upper()
    fname = f"{SCHEMA}.{short}.md" if SCHEMA else f"{short}.md"
    return os.path.join(DOCS_DIR, fname)


def _list_doc_files() -> list[str]:
    try:
        files = [f for f in os.listdir(DOCS_DIR) if f.endswith(".md")]
        if SCHEMA:
            return sorted(f for f in files if f.startswith(f"{SCHEMA}."))
        return sorted(f for f in files if f.upper() != "INDEX.MD")
    except OSError:
        return []


def _parse_index_rows() -> list[dict]:
    """Filas del INDEX.md -> [{object, type, summary, doc_file}]."""
    idx = os.path.join(DOCS_DIR, "INDEX.md")
    out: list[dict] = []
    try:
        with open(idx, encoding="utf-8") as f:
            for line in f:
                m = re.match(
                    r"\|\s*`?([A-Za-z0-9_$#.]+)`?\s*\|\s*([^|]*?)\s*\|\s*(.*?)\s*\|\s*([^|]*?)\s*\|\s*\[?([^\]|]+?)\]?", line
                )
                if not m:
                    continue
                obj = m.group(1).strip()
                if obj.lower() in ("objeto", "object") or set(obj) <= {"-"}:
                    continue
                if SCHEMA and not obj.upper().startswith(f"{SCHEMA}."):
                    obj = f"{SCHEMA}.{obj}"
                out.append({
                    "object": obj,
                    "type": m.group(2).strip(),
                    "summary": m.group(3).strip().replace("\\|", "|"),
                    "doc_file": m.group(5).strip(),
                })
    except OSError:
        pass
    return out
# ---------------------------------------------------------------------------

mcp = FastMCP("consulta_db", host=HOST, port=PORT)

# ---- auth -----------------------------------------------------------------
# Two ways in:
#   1. Static shared secret (MCP_AUTH_TOKEN) via Authorization: Bearer / X-API-Key / ?token=
#      -> handy for curl, Claude Code, scripts.
#   2. OAuth 2.1 Authorization Code + PKCE (see oauth.py) -> what Claude's custom
#      connector "OAuth Client ID/Secret" fields use.
# Auth is REQUIRED unless MCP_AUTH_TOKEN is empty AND no OAuth client is configured.
AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "").strip()
AUTH_REQUIRED = bool(AUTH_TOKEN) or bool(os.environ.get("OAUTH_CLIENT_ID", "").strip())
_AUTH_EXEMPT_PATHS: set[str] = set(oauth.EXEMPT_PATHS)


def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    xkey = request.headers.get("x-api-key")
    if xkey:
        return xkey.strip()
    tok = request.query_params.get("token")
    if tok:
        return tok.strip()
    return None


def _token_ok(token: str | None) -> bool:
    if not token:
        return False
    if AUTH_TOKEN and hmac.compare_digest(token, AUTH_TOKEN):
        return True
    return oauth.validate_access_token(token) is not None


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """Allow requests carrying a valid static token or OAuth access token; else 401."""

    async def dispatch(self, request: Request, call_next):
        if AUTH_REQUIRED and request.url.path not in _AUTH_EXEMPT_PATHS:
            if not _token_ok(_extract_token(request)):
                log.warning(
                    "AUTH DENIED | path=%s client=%s",
                    request.url.path,
                    request.client.host if request.client else "?",
                )
                base = oauth._base_url(request)
                return JSONResponse(
                    {"error": "unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": oauth.www_authenticate_header(base, "invalid_token")},
                )
        return await call_next(request)
# ---------------------------------------------------------------------------


def _dsn() -> str:
    raw_host = os.environ["DB_HOST_PROD_VIEW"].strip()
    service = os.environ["DB_SCHEME_PROD_VIEW"].strip()
    if ":" in raw_host:
        host, port = raw_host.split(":", 1)
        port = int(port)
    else:
        host, port = raw_host, 1521
    return oracledb.makedsn(host, port, service_name=service)


@contextlib.contextmanager
def _connection():
    conn = oracledb.connect(
        user=os.environ["DB_USER_PROD_VIEW"],
        password=os.environ["DB_PASSWORD_PROD_VIEW"],
        dsn=_dsn(),
    )
    try:
        yield conn
    finally:
        conn.close()


def _rows_to_dicts(cursor, limit: int):
    cols = [c[0] for c in cursor.description]
    out = []
    for row in cursor.fetchmany(limit):
        record = {}
        for col, val in zip(cols, row):
            # LOBs and other non-JSON-serialisable types -> str
            if isinstance(val, oracledb.LOB):
                val = val.read()
            record[col] = val
        out.append(record)
    return cols, out


def _clamp_paging(page, page_size):
    page = max(1, int(page))
    page_size = max(1, min(int(page_size), MAX_PAGE_SIZE))
    return page, page_size


def _paginate(conn, base_sql: str, binds: dict, page: int, page_size: int) -> dict:
    """Run `base_sql` (a SELECT) paginated. Returns the standard page envelope.

    Note: pagination is only stable if `base_sql` has a deterministic ORDER BY;
    without one Oracle does not guarantee row order across pages.
    """
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM ({base_sql})", binds)
    total = int(cur.fetchone()[0])
    total_pages = max(1, math.ceil(total / page_size))
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * page_size

    paged_sql = (
        f"SELECT * FROM ({base_sql}) "
        "OFFSET :pg_off ROWS FETCH NEXT :pg_lim ROWS ONLY"
    )
    cur.execute(paged_sql, {**binds, "pg_off": offset, "pg_lim": page_size})
    cols, rows = _rows_to_dicts(cur, page_size)
    return {
        "data": rows,
        "columns": cols,
        "page": page,
        "total_pages": total_pages,
        "total_results": total,
        "page_size": page_size,
    }


_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|merge|drop|create|alter|truncate|grant|revoke|"
    r"commit|rollback|call|execute|begin)\b",
    re.IGNORECASE,
)


@mcp.tool()
def run_query(sql: str, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> dict:
    """Run a read-only SELECT query against the Oracle DB, paginated.

    TIP: si no sabes que tablas/vistas usar, mira primero `search_docs` /
    `get_table_doc` — hay documentacion auto-generada del esquema (para que sirve,
    campos, uniones, notas), que se va actualizando en segundo plano.

    IMPORTANT: schema handling depends on env var `DB_SCHEMA`.
      - If set (e.g. `SC`): qualify every table/view/function — e.g.
        `SELECT * FROM %sx_table`. Queries without the prefix may fail.
      - If unset: write names unqualified (e.g. `SELECT * FROM x_table`); they
        resolve against the connected user's own objects.

    Only SELECT statements are allowed (WITH/CTE is not supported here because the
    query is wrapped in a subquery for paging). Add an explicit ORDER BY for
    stable pages.

    Args:
        sql: the SELECT statement (no trailing semicolon needed).
        page: 1-based page number to fetch.
        page_size: rows per page (max %d).

    Returns a dict: data, columns, page, total_pages, total_results, page_size.
    """ % (SCHEMA_PREFIX, MAX_PAGE_SIZE)
    stmt = sql.strip().rstrip(";").strip()
    if not stmt:
        return {"error": "empty query"}
    lowered = stmt.lstrip("(").lower()
    if not lowered.startswith("select"):
        log.warning("run_query REJECTED (not a SELECT) | sql=%s", _one_line(stmt))
        return {"error": "only SELECT queries are allowed"}
    if _FORBIDDEN.search(stmt):
        log.warning("run_query REJECTED (forbidden keyword) | sql=%s", _one_line(stmt))
        return {"error": "query contains a forbidden (write/DDL) keyword"}
    page, page_size = _clamp_paging(page, page_size)
    log.info("run_query | page=%d page_size=%d | sql=%s", page, page_size, _one_line(stmt))
    try:
        with _connection() as conn:
            result = _paginate(conn, stmt, {}, page, page_size)
        log.info(
            "run_query OK | rows_returned=%d page=%d/%d total_results=%d",
            len(result["data"]), result["page"], result["total_pages"], result["total_results"],
        )
        return result
    except (oracledb.Error, OSError) as e:
        log.warning("run_query FAIL | %s | sql=%s", str(e).replace("\n", " "), _one_line(stmt))
        return {"error": str(e)}


@mcp.tool()
def list_tables(
    name_like: str | None = None, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE
) -> dict:
    """List tables and views available to this connection, paginated.

    If env var `DB_SCHEMA` is set, lists objects owned by that schema (via
    `all_tables`/`all_views`); otherwise lists the current user's own objects
    (via `user_tables`/`user_views`).

    Optional `name_like` filters by name (case-insensitive substring).
    Returns a dict: data, columns, page, total_pages, total_results, page_size.
    Para saber QUE hace cada objeto (no solo el nombre): `search_docs` / `get_table_doc`
    — documentacion auto-generada que se mantiene al dia en segundo plano.
    """
    if SCHEMA:
        base = (
            "SELECT table_name AS name, 'TABLE' AS type FROM all_tables WHERE owner = :own "
            "UNION ALL SELECT view_name AS name, 'VIEW' AS type FROM all_views WHERE owner = :own"
        )
        binds: dict = {"own": SCHEMA}
    else:
        base = (
            "SELECT table_name AS name, 'TABLE' AS type FROM user_tables "
            "UNION ALL SELECT view_name AS name, 'VIEW' AS type FROM user_views"
        )
        binds = {}
    if name_like:
        base = f"SELECT * FROM ({base}) WHERE UPPER(name) LIKE :flt"
        binds["flt"] = f"%{name_like.upper()}%"
    base = f"SELECT name, type FROM ({base}) ORDER BY name"
    page, page_size = _clamp_paging(page, page_size)
    log.info("list_tables | name_like=%r page=%d page_size=%d", name_like, page, page_size)
    try:
        with _connection() as conn:
            result = _paginate(conn, base, binds, page, page_size)
        log.info(
            "list_tables OK | rows_returned=%d page=%d/%d total_results=%d",
            len(result["data"]), result["page"], result["total_pages"], result["total_results"],
        )
        return result
    except (oracledb.Error, OSError) as e:
        log.warning("list_tables FAIL | %s", str(e).replace("\n", " "))
        return {"error": str(e)}


@mcp.tool()
def describe_table(table_name: str) -> dict:
    """Return the column definitions (name, type, length, nullable) of a table or view.

    `table_name` may be given with or without the schema prefix. If `DB_SCHEMA`
    is unset, the lookup uses `user_tab_columns` (current user's own objects);
    otherwise it uses `all_tab_columns` filtered by owner.
    """
    name = table_name.split(".", 1)[-1].strip().strip('"').upper()
    if SCHEMA:
        sql = (
            "SELECT column_name, data_type, data_length, data_precision, "
            "data_scale, nullable FROM all_tab_columns "
            "WHERE owner = :own AND table_name = :t ORDER BY column_id"
        )
        binds = {"own": SCHEMA, "t": name}
    else:
        sql = (
            "SELECT column_name, data_type, data_length, data_precision, "
            "data_scale, nullable FROM user_tab_columns "
            "WHERE table_name = :t ORDER BY column_id"
        )
        binds = {"t": name}
    fq = _qualify(name)
    log.info("describe_table | table=%s", fq)
    try:
        with _connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, binds)
            cols, rows = _rows_to_dicts(cur, MAX_PAGE_SIZE)
            if not rows:
                log.info("describe_table | table=%s not found/visible", fq)
                return {"error": f"table/view '{fq}' not found or not visible"}
            log.info("describe_table OK | table=%s columns=%d", fq, len(rows))
            return {"table": fq, "columns": rows}
    except (oracledb.Error, OSError) as e:
        log.warning("describe_table FAIL | table=%s | %s", table_name, str(e).replace("\n", " "))
        return {"error": str(e)}


@mcp.tool()
def search_docs(query: str = "", limit: int = 20) -> dict:
    """Buscar en la documentacion del esquema (carpeta `docs/` de este MCP).

    Empieza por aqui cuando no sepas que tabla/vista/funcion usar: hay un Markdown
    por objeto (para que sirve, campos, tipos, llaves, uniones), generado a partir de
    comentarios + estructura + muestras de datos. **Esta documentacion se actualiza
    periodicamente** (la mantiene una sesion de Claude siguiendo `PROMPT_DOCUMENTAR.md`),
    asi que puede ir por detras de la BD real o no cubrir todos los objetos todavia —
    para lo exacto/al dia usa `describe_table` / `run_query`.

    Args:
        query: terminos a buscar (en nombres y descripciones de los objetos y en el
            cuerpo de cada doc). Vacio => devuelve el indice completo (catalogo).
        limit: maximo de resultados.

    Devuelve: {results: [{object, type, summary, doc_file, score, snippet}],
    total_documented, total_in_schema, hint}. Para el detalle de uno: `get_table_doc`.
    """
    rows = _parse_index_rows()
    files = _list_doc_files()
    if not files and not rows:
        return {
            "results": [],
            "total_documented": 0,
            "hint": (
                "Aun no hay documentacion generada en " + DOCS_DIR + ". Usa `list_tables` "
                "y `describe_table` mientras tanto; la doc se va creando con `PROMPT_DOCUMENTAR.md`."
            ),
        }

    by_obj = {r["object"].upper(): r for r in rows}
    terms = [t for t in re.split(r"\s+", query.strip().lower()) if t]

    def short_name(fn: str) -> str:
        n = fn[:-3] if fn.endswith(".md") else fn
        if SCHEMA and not n.upper().startswith(f"{SCHEMA}."):
            return f"{SCHEMA}.{n}"
        return n

    scored = []
    for fn in files:
        obj = short_name(fn)
        meta = by_obj.get(obj.upper(), {"object": obj, "type": "?", "summary": "", "doc_file": fn})
        try:
            with open(os.path.join(DOCS_DIR, fn), encoding="utf-8") as f:
                body = f.read()
        except OSError:
            body = ""
        low = body.lower()
        name_l = obj.lower()
        summ_l = (meta.get("summary") or "").lower()
        if not terms:
            score = 1
            snippet = (meta.get("summary") or "")[:200]
        else:
            score = 0
            snippet = ""
            for t in terms:
                if t in name_l:
                    score += 10
                if t in summ_l:
                    score += 5
                c = low.count(t)
                if c:
                    score += min(c, 5)
                    if not snippet:
                        i = low.find(t)
                        s = max(0, i - 80)
                        snippet = ("…" if s else "") + body[s:i + 120].replace("\n", " ").strip() + "…"
            if score == 0:
                continue
        scored.append({
            "object": obj,
            "type": meta.get("type", "?"),
            "summary": meta.get("summary", ""),
            "doc_file": fn,
            "score": score,
            "snippet": snippet or (meta.get("summary") or "")[:200],
        })

    scored.sort(key=lambda r: (-r["score"], r["object"]))
    total_in_schema = None
    try:
        with open(os.path.join(DOCS_DIR, "INDEX.md"), encoding="utf-8") as f:
            m = re.search(r"de\s+(\d+)\*\*\s+objetos", f.read())
            if m:
                total_in_schema = int(m.group(1))
    except OSError:
        pass
    log.info("search_docs | query=%r results=%d/%d", query, min(len(scored), limit), len(files))
    return {
        "results": scored[: max(1, limit)],
        "total_documented": len(files),
        "total_in_schema": total_in_schema,
        "hint": "Doc auto-generada y en actualizacion continua; si un objeto no aparece usa `describe_table`.",
    }


@mcp.tool()
def get_table_doc(table_name: str) -> dict:
    """Devolver la documentacion (Markdown) de un objeto del esquema.

    `table_name` con o sin prefijo de esquema (p. ej. `<SCHEMA>.<TABLE>` o
    `<table>`). Tambien acepta `"INDEX"` para el catalogo completo.

    La doc la mantiene una sesion de Claude (ver `PROMPT_DOCUMENTAR.md`) a partir de
    comentarios + estructura + muestras, y **se actualiza periodicamente**; para el
    detalle exacto/al dia usa `describe_table` / `run_query`. Si el objeto aun no esta
    documentado, devuelve error con esa indicacion.
    """
    path = _doc_path(table_name)
    log.info("get_table_doc | table=%s -> %s", table_name, os.path.basename(path))
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
    except OSError:
        avail = ", ".join(f[:-3] for f in _list_doc_files()[:50]) or "(ninguna todavia)"
        return {
            "error": (
                f"no hay doc generada para '{table_name}'. Usa `describe_table('{table_name}')` "
                f"para la estructura, o `search_docs()` para ver que hay. La doc se va creando "
                f"con `PROMPT_DOCUMENTAR.md`. Documentadas: {avail}"
            )
        }
    return {"object": os.path.basename(path)[:-3], "markdown": content, "note": "auto-generada; se actualiza periodicamente"}


@mcp.tool()
def ping() -> dict:
    """Check DB connectivity. Returns the DB time and version on success."""
    log.info("ping")
    try:
        with _connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT SYSTIMESTAMP FROM dual")
            (now,) = cur.fetchone()
            log.info("ping OK | db_time=%s", now)
            return {"ok": True, "db_time": str(now), "client_version": oracledb.__version__}
    except (oracledb.Error, OSError) as e:
        log.warning("ping FAIL | %s", str(e).replace("\n", " "))
        return {"ok": False, "error": str(e)}


def _startup_check() -> None:
    """Print DB credentials and run a connection test at startup."""
    host_raw = os.environ.get("DB_HOST_PROD_VIEW", "").strip()
    service  = os.environ.get("DB_SCHEME_PROD_VIEW", "").strip()
    user     = os.environ.get("DB_USER_PROD_VIEW", "").strip()
    password = os.environ.get("DB_PASSWORD_PROD_VIEW", "").strip()

    masked_pw = (password[:2] + "*" * (len(password) - 2)) if len(password) > 2 else "***"
    print("=" * 60)
    print("  DB_HOST_PROD_VIEW  :", host_raw  or "(vacío)")
    print("  DB_SCHEME_PROD_VIEW:", service   or "(vacío)")
    print("  DB_USER_PROD_VIEW  :", user      or "(vacío)")
    print("  DB_PASSWORD_PROD_VIEW:", masked_pw)
    print("  DB_SCHEMA          :", SCHEMA    or "(sin prefijo)")
    print("=" * 60)

    log.info(
        "startup | host=%s service=%s user=%s schema=%s",
        host_raw, service, user, SCHEMA or "(none)",
    )

    print("Probando conexión a la base de datos...")
    try:
        with _connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT SYSTIMESTAMP FROM dual")
            (db_time,) = cur.fetchone()
        print(f"  Conexión OK — db_time={db_time}  oracledb={oracledb.__version__}")
        log.info("startup connection test OK | db_time=%s", db_time)
    except (oracledb.Error, OSError) as exc:
        msg = str(exc).replace("\n", " ")
        print(f"  Conexión FALLIDA — {msg}")
        log.error("startup connection test FAIL | %s", msg)
    print("=" * 60)


if __name__ == "__main__":
    if AUTH_REQUIRED:
        modes = []
        if AUTH_TOKEN:
            modes.append("static token (Bearer / X-API-Key / ?token=)")
        modes.append("OAuth2 authorization_code + PKCE")
        log.info("auth: ENABLED — %s", " + ".join(modes))
    else:
        log.warning("auth: DISABLED — set MCP_AUTH_TOKEN and/or OAUTH_CLIENT_ID to require auth")

    _startup_check()
    log.info("starting consulta_db MCP on %s:%d (logs -> %s)", HOST, PORT, LOG_FILE)

    app = mcp.streamable_http_app()
    oauth.mount(app)
    app.add_middleware(TokenAuthMiddleware)
    try:
        uvicorn.run(app, host=HOST, port=PORT, log_level="info")
    except KeyboardInterrupt:
        pass
    finally:
        log.info("consulta_db MCP stopped")
