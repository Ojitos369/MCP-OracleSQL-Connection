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
import uuid
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
def explain_plan(sql: str, format: str = "TYPICAL") -> dict:
    """Mostrar el PLAN DE EJECUCION que Oracle elegiria para un SELECT (sin correrlo).

    Usa `EXPLAIN PLAN FOR <sql>` + `DBMS_XPLAN.DISPLAY`. NO ejecuta la query: solo
    pide al optimizador el plan estimado (accesos a tabla full vs index, orden y
    metodo de joins, costo y filas estimadas). Util para diagnosticar queries lentas
    antes de optimizar.

    Mismo manejo de esquema que `run_query`: si `DB_SCHEMA` esta seteado, califica
    las tablas/vistas (p. ej. `%sx_table`).

    Args:
        sql: el SELECT a analizar (sin punto y coma final). Solo SELECT.
        format: formato de DBMS_XPLAN.DISPLAY: 'BASIC', 'TYPICAL' (default),
            'ALL', 'ADVANCED'. Mas detalle = mas verboso.

    Devuelve: {plan: texto del plan, plan_lines: [str], sql, format}. El plan es
    ESTIMADO; para el plan real (filas/buffers efectivos) hay que ejecutar la query
    con GATHER_PLAN_STATISTICS y DBMS_XPLAN.DISPLAY_CURSOR.
    """ % SCHEMA_PREFIX
    stmt = sql.strip().rstrip(";").strip()
    if not stmt:
        return {"error": "empty query"}
    lowered = stmt.lstrip("(").lower()
    if not lowered.startswith("select"):
        log.warning("explain_plan REJECTED (not a SELECT) | sql=%s", _one_line(stmt))
        return {"error": "only SELECT queries are allowed"}
    if _FORBIDDEN.search(stmt):
        log.warning("explain_plan REJECTED (forbidden keyword) | sql=%s", _one_line(stmt))
        return {"error": "query contains a forbidden (write/DDL) keyword"}
    fmt = (format or "TYPICAL").strip().upper()
    if fmt not in ("BASIC", "TYPICAL", "ALL", "ADVANCED"):
        return {"error": "format must be one of BASIC, TYPICAL, ALL, ADVANCED"}
    # statement_id unico (inline, EXPLAIN PLAN no admite bind aqui) -> alfanumerico seguro.
    sid = "mcp_" + uuid.uuid4().hex[:24]
    log.info("explain_plan | format=%s | sql=%s", fmt, _one_line(stmt))
    try:
        with _connection() as conn:
            cur = conn.cursor()
            # EXPLAIN PLAN inserta en PLAN_TABLE; cerramos sin commit -> se descarta.
            cur.execute(f"EXPLAIN PLAN SET STATEMENT_ID = '{sid}' FOR {stmt}")
            cur.execute(
                "SELECT plan_table_output FROM "
                "TABLE(DBMS_XPLAN.DISPLAY('PLAN_TABLE', :sid, :fmt))",
                {"sid": sid, "fmt": fmt},
            )
            lines = [r[0] for r in cur.fetchall()]
        log.info("explain_plan OK | lines=%d", len(lines))
        return {
            "sql": stmt,
            "format": fmt,
            "plan_lines": lines,
            "plan": "\n".join(lines),
        }
    except (oracledb.Error, OSError) as e:
        log.warning("explain_plan FAIL | %s | sql=%s", str(e).replace("\n", " "), _one_line(stmt))
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
                # Puede ser un sinonimo hacia una tabla de otro schema: seguirlo.
                tgt = _synonym_target(cur, name)
                if tgt:
                    cur.execute(
                        "SELECT column_name, data_type, data_length, data_precision, "
                        "data_scale, nullable FROM all_tab_columns "
                        "WHERE owner = :own AND table_name = :t ORDER BY column_id",
                        {"own": tgt[0], "t": tgt[1]},
                    )
                    cols, rows = _rows_to_dicts(cur, MAX_PAGE_SIZE)
                    if rows:
                        log.info(
                            "describe_table OK | table=%s synonym_for=%s.%s columns=%d",
                            fq, tgt[0], tgt[1], len(rows),
                        )
                        return {
                            "table": fq,
                            "synonym_for": f"{tgt[0]}.{tgt[1]}",
                            "columns": rows,
                        }
                log.info("describe_table | table=%s not found/visible", fq)
                return {"error": f"table/view '{fq}' not found or not visible"}
            log.info("describe_table OK | table=%s columns=%d", fq, len(rows))
            return {"table": fq, "columns": rows}
    except (oracledb.Error, OSError) as e:
        log.warning("describe_table FAIL | table=%s | %s", table_name, str(e).replace("\n", " "))
        return {"error": str(e)}


# ---- objetos del esquema: triggers, procedimientos, funciones, dependencias --
_PLSQL_TYPES = ("PROCEDURE", "FUNCTION", "PACKAGE", "PACKAGE BODY", "TYPE", "TYPE BODY", "TRIGGER")
_KNOWN_OBJECT_TYPES = _PLSQL_TYPES + (
    "TABLE", "VIEW", "MATERIALIZED VIEW", "SEQUENCE", "SYNONYM", "INDEX",
)
# Orden de preferencia al resolver el tipo cuando hay varios objetos con el mismo nombre.
_TYPE_PRIORITY = (
    "VIEW", "TRIGGER", "PROCEDURE", "FUNCTION", "PACKAGE BODY", "PACKAGE",
    "TYPE BODY", "TYPE", "MATERIALIZED VIEW", "TABLE", "SYNONYM", "INDEX", "SEQUENCE",
)


def _clean_name(name: str) -> str:
    """'SCHEMA.X' / '"x"' -> 'X' (nombre pelado en mayusculas)."""
    return name.split(".", 1)[-1].strip().strip('"').upper()


def _synonym_target(cur, name: str) -> tuple[str, str] | None:
    """Si `name` es un sinonimo del esquema configurado (o del usuario conectado),
    devuelve (owner, nombre) del objeto real al que apunta; si no, None."""
    if SCHEMA:
        cur.execute(
            "SELECT table_owner, table_name FROM all_synonyms "
            "WHERE owner = :own AND synonym_name = :n",
            {"own": SCHEMA, "n": name},
        )
    else:
        cur.execute(
            "SELECT table_owner, table_name FROM user_synonyms WHERE synonym_name = :n",
            {"n": name},
        )
    row = cur.fetchone()
    return (row[0], row[1]) if row else None


@mcp.tool()
def list_objects(
    object_type: str | None = None,
    name_like: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> dict:
    """Listar TODOS los objetos del esquema (no solo tablas/vistas), paginado.

    Complementa a `list_tables`: aqui aparecen tambien TRIGGER, PROCEDURE,
    FUNCTION, PACKAGE, PACKAGE BODY, TYPE, SEQUENCE, SYNONYM, INDEX,
    MATERIALIZED VIEW, etc. Para ver el codigo de uno: `get_object_source`.
    Para saber quien lo usa / que usa: `used_by`.

    Args:
        object_type: filtra por tipo exacto (p. ej. 'TRIGGER', 'PROCEDURE',
            'FUNCTION', 'PACKAGE', 'VIEW', 'TABLE'). None => todos.
        name_like: substring del nombre (case-insensitive).
        page / page_size: paginacion estandar.

    Devuelve: data (name, type, status, last_ddl_time), columns, page,
    total_pages, total_results, page_size.
    """
    if SCHEMA:
        # all_objects se complementa con all_triggers/all_tables/all_views porque
        # con ciertos privilegios (p. ej. SELECT ANY TABLE) esos objetos son
        # visibles en sus vistas propias pero NO aparecen en all_objects.
        inner = (
            "SELECT object_name AS name, object_type AS type, status, "
            "TO_CHAR(last_ddl_time, 'YYYY-MM-DD HH24:MI:SS') AS last_ddl_time "
            "FROM all_objects WHERE owner = :own "
            "UNION ALL "
            "SELECT t.trigger_name, 'TRIGGER', t.status, NULL FROM all_triggers t "
            "WHERE t.owner = :own AND NOT EXISTS (SELECT 1 FROM all_objects o "
            "WHERE o.owner = :own AND o.object_name = t.trigger_name AND o.object_type = 'TRIGGER') "
            "UNION ALL "
            "SELECT tb.table_name, 'TABLE', NULL, NULL FROM all_tables tb "
            "WHERE tb.owner = :own AND NOT EXISTS (SELECT 1 FROM all_objects o "
            "WHERE o.owner = :own AND o.object_name = tb.table_name AND o.object_type = 'TABLE') "
            "UNION ALL "
            "SELECT v.view_name, 'VIEW', NULL, NULL FROM all_views v "
            "WHERE v.owner = :own AND NOT EXISTS (SELECT 1 FROM all_objects o "
            "WHERE o.owner = :own AND o.object_name = v.view_name AND o.object_type = 'VIEW') "
            "UNION ALL "
            "SELECT s.synonym_name, 'SYNONYM', NULL, NULL FROM all_synonyms s "
            "WHERE s.owner = :own AND NOT EXISTS (SELECT 1 FROM all_objects o "
            "WHERE o.owner = :own AND o.object_name = s.synonym_name AND o.object_type = 'SYNONYM')"
        )
        binds: dict = {"own": SCHEMA}
    else:
        inner = (
            "SELECT object_name AS name, object_type AS type, status, "
            "TO_CHAR(last_ddl_time, 'YYYY-MM-DD HH24:MI:SS') AS last_ddl_time "
            "FROM user_objects"
        )
        binds = {}
    base = f"SELECT name, type, status, last_ddl_time FROM ({inner}) WHERE 1 = 1"
    if object_type:
        base += " AND type = :otype"
        binds["otype"] = object_type.strip().upper()
    if name_like:
        base += " AND UPPER(name) LIKE :flt"
        binds["flt"] = f"%{name_like.upper()}%"
    base += " ORDER BY name, type"
    page, page_size = _clamp_paging(page, page_size)
    log.info(
        "list_objects | object_type=%r name_like=%r page=%d page_size=%d",
        object_type, name_like, page, page_size,
    )
    try:
        with _connection() as conn:
            result = _paginate(conn, base, binds, page, page_size)
        log.info(
            "list_objects OK | rows_returned=%d page=%d/%d total_results=%d",
            len(result["data"]), result["page"], result["total_pages"], result["total_results"],
        )
        if not result["data"] and object_type and object_type.strip().upper() not in _KNOWN_OBJECT_TYPES:
            result["hint"] = f"tipo '{object_type}' no reconocido; tipos comunes: {', '.join(_KNOWN_OBJECT_TYPES)}"
        return result
    except (oracledb.Error, OSError) as e:
        log.warning("list_objects FAIL | %s", str(e).replace("\n", " "))
        return {"error": str(e)}


@mcp.tool()
def used_by(
    object_name: str,
    direction: str = "used_by",
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> dict:
    """Dependencias de un objeto: DONDE SE USA una tabla/vista/funcion (o que usa el).

    Lee `all_dependencies` (diccionario de Oracle). Dos direcciones:
      - direction='used_by' (default): objetos que REFERENCIAN a `object_name`
        (vistas, triggers, procedimientos, funciones, packages que lo usan).
        Ideal para responder "¿donde se utiliza esta tabla?".
      - direction='uses': objetos que `object_name` referencia (sus dependencias).

    Nota: solo cubre referencias registradas por Oracle (PL/SQL, vistas, triggers).
    SQL dinamico o queries desde aplicaciones externas NO aparecen aqui.

    Args:
        object_name: nombre del objeto, con o sin prefijo de esquema.
        direction: 'used_by' | 'uses'.
        page / page_size: paginacion estandar.

    Devuelve: data (owner, name, type — o referenced_* si direction='uses'),
    columns, page, total_pages, total_results, page_size.
    """
    name = _clean_name(object_name)
    dirn = (direction or "used_by").strip().lower()
    if dirn not in ("used_by", "uses"):
        return {"error": "direction must be 'used_by' or 'uses'"}
    page, page_size = _clamp_paging(page, page_size)
    log.info("used_by | object=%s direction=%s page=%d page_size=%d", _qualify(name), dirn, page, page_size)
    try:
        with _connection() as conn:
            # Si el nombre es un sinonimo, buscar tambien referencias al objeto real
            # (las dependencias pueden registrarse contra uno u otro).
            tgt = _synonym_target(conn.cursor(), name)
            if dirn == "used_by":
                dep_view = "all_dependencies" if SCHEMA else "user_dependencies"
                owner_col = "owner" if SCHEMA else "USER AS owner"
                cond = "(referenced_owner = :own AND referenced_name = :n)"
                binds: dict = {"own": SCHEMA or "", "n": name}
                if not SCHEMA:
                    cond = "(referenced_owner = USER AND referenced_name = :n)"
                    binds = {"n": name}
                if tgt:
                    cond += " OR (referenced_owner = :town AND referenced_name = :tn)"
                    binds.update({"town": tgt[0], "tn": tgt[1]})
                base = (
                    f"SELECT {owner_col}, name, type FROM {dep_view} "
                    f"WHERE {cond} ORDER BY type, name"
                )
            else:
                dep_view = "all_dependencies" if SCHEMA else "user_dependencies"
                cond = "(owner = :own AND name = :n)" if SCHEMA else "name = :n"
                binds = {"own": SCHEMA, "n": name} if SCHEMA else {"n": name}
                if tgt and SCHEMA:
                    cond += " OR (owner = :town AND name = :tn)"
                    binds.update({"town": tgt[0], "tn": tgt[1]})
                base = (
                    f"SELECT referenced_owner, referenced_name, referenced_type "
                    f"FROM {dep_view} WHERE {cond} "
                    "ORDER BY referenced_type, referenced_owner, referenced_name"
                )
            result = _paginate(conn, base, binds, page, page_size)
            if tgt:
                result["synonym_for"] = f"{tgt[0]}.{tgt[1]}"
        log.info(
            "used_by OK | object=%s direction=%s total_results=%d",
            _qualify(name), dirn, result["total_results"],
        )
        result["object"] = _qualify(name)
        result["direction"] = dirn
        if not result["data"]:
            result["hint"] = (
                "sin dependencias registradas; recuerda que SQL dinamico y apps externas "
                "no aparecen en all_dependencies. Para triggers sobre una tabla usa `list_triggers`."
            )
        return result
    except (oracledb.Error, OSError) as e:
        log.warning("used_by FAIL | object=%s | %s", object_name, str(e).replace("\n", " "))
        return {"error": str(e)}


@mcp.tool()
def list_triggers(
    table_name: str | None = None,
    name_like: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> dict:
    """Listar triggers del esquema, opcionalmente filtrados por la tabla que disparan.

    Lee `all_triggers`. Muestra sobre que tabla actua cada trigger, el evento
    (INSERT/UPDATE/DELETE), tipo (BEFORE/AFTER, ROW/STATEMENT) y estado.
    Para ver el cuerpo completo de uno: `get_object_source(nombre, 'TRIGGER')`.

    Args:
        table_name: filtra los triggers de esa tabla (con o sin prefijo de esquema).
        name_like: substring del nombre del trigger (case-insensitive).
        page / page_size: paginacion estandar.

    Devuelve: data (trigger_name, table_name, trigger_type, triggering_event,
    status), columns, page, total_pages, total_results, page_size.
    """
    if SCHEMA:
        base = (
            "SELECT trigger_name, table_name, trigger_type, triggering_event, status "
            "FROM all_triggers WHERE owner = :own"
        )
        binds: dict = {"own": SCHEMA}
    else:
        base = (
            "SELECT trigger_name, table_name, trigger_type, triggering_event, status "
            "FROM user_triggers WHERE 1 = 1"
        )
        binds = {}
    if table_name:
        base += " AND table_name = :t"
        binds["t"] = _clean_name(table_name)
    if name_like:
        base += " AND UPPER(trigger_name) LIKE :flt"
        binds["flt"] = f"%{name_like.upper()}%"
    base += " ORDER BY trigger_name"
    page, page_size = _clamp_paging(page, page_size)
    log.info(
        "list_triggers | table=%r name_like=%r page=%d page_size=%d",
        table_name, name_like, page, page_size,
    )
    try:
        with _connection() as conn:
            result = _paginate(conn, base, binds, page, page_size)
        log.info(
            "list_triggers OK | rows_returned=%d total_results=%d",
            len(result["data"]), result["total_results"],
        )
        return result
    except (oracledb.Error, OSError) as e:
        log.warning("list_triggers FAIL | %s", str(e).replace("\n", " "))
        return {"error": str(e)}


@mcp.tool()
def get_object_source(
    object_name: str,
    object_type: str | None = None,
    page: int = 1,
    page_size: int = 500,
) -> dict:
    """Ver el CODIGO FUENTE / definicion de un objeto: trigger, procedimiento,
    funcion, package, type, vista, tabla, etc.

    Segun el tipo:
      - PROCEDURE / FUNCTION / PACKAGE / PACKAGE BODY / TYPE / TYPE BODY:
        fuente PL/SQL desde `all_source`, paginada por lineas.
      - TRIGGER: cabecera + cuerpo desde `all_triggers` (tabla, evento, estado).
      - VIEW: el SELECT que la define (`all_views`).
      - MATERIALIZED VIEW: la query (`all_mviews`).
      - TABLE / INDEX / SEQUENCE / SYNONYM: intenta el DDL via
        `DBMS_METADATA.GET_DDL` (puede fallar sin privilegios; para columnas de
        una tabla usa mejor `describe_table`).

    Args:
        object_name: nombre con o sin prefijo de esquema.
        object_type: tipo exacto (p. ej. 'TRIGGER', 'PACKAGE BODY'). None =>
            se resuelve solo; si hay varios objetos con ese nombre se prefiere
            el que tiene codigo (body sobre spec) y se listan los demas en
            `types_found`.
        page / page_size: paginacion POR LINEAS del fuente PL/SQL (default 500,
            max %d). Vistas/triggers/DDL se devuelven completos sin paginar.

    Devuelve: {object, type, source, ...} (+ line_count/page/total_pages si es
    fuente paginado; + table_name/triggering_event/status si es trigger).
    """ % MAX_PAGE_SIZE
    name = _clean_name(object_name)
    otype = object_type.strip().upper() if object_type else None
    log.info("get_object_source | object=%s type=%r", _qualify(name), otype)

    def _types_at(cur, own: str, n: str) -> list[str]:
        # No basta all_objects: con privilegios tipo SELECT ANY TABLE hay objetos
        # visibles en sus vistas de diccionario propias que all_objects no lista.
        cur.execute(
            "SELECT object_type FROM all_objects WHERE owner = :own AND object_name = :n "
            "UNION SELECT 'TRIGGER' FROM all_triggers WHERE owner = :own AND trigger_name = :n "
            "UNION SELECT 'TABLE' FROM all_tables WHERE owner = :own AND table_name = :n "
            "UNION SELECT 'VIEW' FROM all_views WHERE owner = :own AND view_name = :n "
            "UNION SELECT 'SYNONYM' FROM all_synonyms WHERE owner = :own AND synonym_name = :n "
            "UNION SELECT DISTINCT type FROM all_source WHERE owner = :own AND name = :n",
            {"own": own, "n": n},
        )
        return sorted({r[0] for r in cur.fetchall()})

    try:
        with _connection() as conn:
            cur = conn.cursor()
            if SCHEMA:
                own = SCHEMA
            else:
                cur.execute("SELECT USER FROM dual")
                own = cur.fetchone()[0]

            types_found = _types_at(cur, own, name)
            if not types_found:
                return {"error": f"objeto '{_qualify(name)}' no encontrado o no visible"}

            # Si el nombre es SOLO un sinonimo, seguirlo hasta el objeto real
            # (el esquema puede exponer tablas de otros schemas via sinonimos).
            synonym_for = None
            hops = 0
            while types_found == ["SYNONYM"] and otype != "SYNONYM" and hops < 5:
                cur.execute(
                    "SELECT table_owner, table_name FROM all_synonyms "
                    "WHERE owner = :own AND synonym_name = :n",
                    {"own": own, "n": name},
                )
                row = cur.fetchone()
                if not row:
                    break
                own, name = row[0], row[1]
                synonym_for = f"{own}.{name}"
                types_found = _types_at(cur, own, name)
                hops += 1
            if not types_found:
                return {
                    "error": (
                        f"'{_qualify(_clean_name(object_name))}' es un sinonimo hacia "
                        f"'{synonym_for}' pero el destino no es visible para este usuario"
                    )
                }

            if otype is None:
                otype = min(
                    types_found,
                    key=lambda t: _TYPE_PRIORITY.index(t) if t in _TYPE_PRIORITY else 99,
                )
            elif otype not in types_found:
                return {
                    "error": f"'{_qualify(_clean_name(object_name))}' no existe como {otype}",
                    "types_found": types_found,
                }

            fq = f"{own}.{name}"
            out: dict = {"object": fq, "type": otype, "types_found": types_found}
            if synonym_for:
                out["requested"] = _qualify(_clean_name(object_name))
                out["synonym_for"] = synonym_for

            if otype == "TRIGGER":
                cur.execute(
                    "SELECT table_name, trigger_type, triggering_event, status, "
                    "description, trigger_body FROM all_triggers "
                    "WHERE owner = :own AND trigger_name = :n",
                    {"own": own, "n": name},
                )
                row = cur.fetchone()
                if not row:
                    return {"error": f"trigger '{fq}' no encontrado"}
                tbl, ttype, tevent, status, desc, body = row
                out.update({
                    "table_name": tbl,
                    "trigger_type": ttype,
                    "triggering_event": tevent,
                    "status": status,
                    "source": f"TRIGGER {desc.strip() if desc else name}\n{body or ''}",
                })
                log.info("get_object_source OK | trigger=%s table=%s", fq, tbl)
                return out

            if otype == "VIEW":
                cur.execute(
                    "SELECT text FROM all_views WHERE owner = :own AND view_name = :n",
                    {"own": own, "n": name},
                )
                row = cur.fetchone()
                out["source"] = row[0] if row else ""
                log.info("get_object_source OK | view=%s", fq)
                return out

            if otype == "MATERIALIZED VIEW":
                cur.execute(
                    "SELECT query FROM all_mviews WHERE owner = :own AND mview_name = :n",
                    {"own": own, "n": name},
                )
                row = cur.fetchone()
                val = row[0] if row else ""
                out["source"] = val.read() if isinstance(val, oracledb.LOB) else val
                log.info("get_object_source OK | mview=%s", fq)
                return out

            if otype in _PLSQL_TYPES:
                base = (
                    "SELECT line, text FROM all_source "
                    "WHERE owner = :own AND name = :n AND type = :t ORDER BY line"
                )
                binds = {"own": own, "n": name, "t": otype}
                page, page_size = _clamp_paging(page, page_size)
                result = _paginate(conn, base, binds, page, page_size)
                out.update({
                    "source": "".join(r["TEXT"] or "" for r in result["data"]),
                    "line_count": result["total_results"],
                    "page": result["page"],
                    "total_pages": result["total_pages"],
                    "page_size": result["page_size"],
                })
                log.info(
                    "get_object_source OK | %s=%s lines=%d page=%d/%d",
                    otype, fq, result["total_results"], result["page"], result["total_pages"],
                )
                return out

            # TABLE / INDEX / SEQUENCE / SYNONYM / otros: intentar DDL.
            try:
                cur.execute(
                    "SELECT DBMS_METADATA.GET_DDL(:t, :n, :own) FROM dual",
                    {"t": otype.replace(" ", "_"), "n": name, "own": own},
                )
                row = cur.fetchone()
                val = row[0] if row else ""
                out["source"] = val.read() if isinstance(val, oracledb.LOB) else str(val or "")
                log.info("get_object_source OK | ddl %s=%s", otype, fq)
                return out
            except oracledb.Error as e:
                out["error"] = (
                    f"sin acceso al DDL de {otype} ({str(e).splitlines()[0]}). "
                    "Para tablas usa `describe_table`; para triggers de la tabla, `list_triggers`."
                )
                return out
    except (oracledb.Error, OSError) as e:
        log.warning("get_object_source FAIL | object=%s | %s", object_name, str(e).replace("\n", " "))
        return {"error": str(e)}


@mcp.tool()
def describe_procedure(object_name: str, package_name: str | None = None) -> dict:
    """Firma (argumentos) de un procedimiento o funcion, incluso dentro de un package.

    Lee `all_arguments`: nombre, posicion, tipo de dato, IN/OUT, default, overload.
    La fila con posicion 0 es el valor de RETORNO (solo funciones). Para el cuerpo
    completo usa `get_object_source`.

    Args:
        object_name: nombre del procedimiento/funcion (con o sin prefijo de esquema).
        package_name: si vive dentro de un package, el nombre del package.

    Devuelve: {object, package, arguments: [{argument_name, position, data_type,
    in_out, defaulted, overload}]}.
    """
    name = _clean_name(object_name)
    pkg = _clean_name(package_name) if package_name else None
    view = "all_arguments" if SCHEMA else "user_arguments"
    sql = (
        f"SELECT overload, position, argument_name, data_type, in_out, defaulted "
        f"FROM {view} WHERE object_name = :n"
    )
    binds: dict = {"n": name}
    if SCHEMA:
        sql += " AND owner = :own"
        binds["own"] = SCHEMA
    if pkg:
        sql += " AND package_name = :p"
        binds["p"] = pkg
    else:
        sql += " AND package_name IS NULL"
    sql += " ORDER BY overload NULLS FIRST, position"
    log.info("describe_procedure | object=%s package=%r", _qualify(name), pkg)
    try:
        with _connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, binds)
            cols, rows = _rows_to_dicts(cur, MAX_PAGE_SIZE)
            if not rows:
                # Puede ser un sinonimo hacia un proc/func/package de otro schema.
                tgt = _synonym_target(cur, pkg or name)
                if tgt:
                    town, tname = tgt
                    sql2 = (
                        "SELECT overload, position, argument_name, data_type, in_out, defaulted "
                        "FROM all_arguments WHERE owner = :own AND object_name = :n"
                    )
                    binds2: dict = {"own": town, "n": name if pkg else tname}
                    if pkg:
                        sql2 += " AND package_name = :p"
                        binds2["p"] = tname
                    else:
                        sql2 += " AND package_name IS NULL"
                    sql2 += " ORDER BY overload NULLS FIRST, position"
                    cur.execute(sql2, binds2)
                    cols, rows = _rows_to_dicts(cur, MAX_PAGE_SIZE)
                    if rows:
                        log.info(
                            "describe_procedure OK | object=%s synonym_for=%s.%s args=%d",
                            _qualify(name), town, tname, len(rows),
                        )
                        return {
                            "object": _qualify(name),
                            "package": pkg,
                            "synonym_for": f"{town}.{tname}",
                            "arguments": rows,
                        }
                hint = (
                    f"'{_qualify(name)}' sin argumentos registrados o no existe"
                    + (f" en el package {pkg}" if pkg else "")
                    + ". Si vive en un package, pasa package_name; verifica con "
                    "`list_objects(object_type='PROCEDURE')` o 'FUNCTION'."
                )
                return {"object": _qualify(name), "package": pkg, "arguments": [], "hint": hint}
            log.info("describe_procedure OK | object=%s args=%d", _qualify(name), len(rows))
            return {"object": _qualify(name), "package": pkg, "arguments": rows}
    except (oracledb.Error, OSError) as e:
        log.warning("describe_procedure FAIL | object=%s | %s", object_name, str(e).replace("\n", " "))
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
