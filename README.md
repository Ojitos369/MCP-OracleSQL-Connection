# consulta_db — MCP server (Oracle SQL, solo lectura)

Servidor MCP que expone consultas de **solo lectura** contra la base Oracle de la
vista de producción. Transporte: Streamable HTTP en `MCP_HOST:MCP_PORT`, ruta `/mcp`.
`MCP_PORT` es **obligatorio** (no hay valor por defecto); `MCP_HOST` por defecto `0.0.0.0`.

## Setup (uv)

```bash
cd consulta_db
uv sync                   # crea .venv e instala deps
cp .env.example .env      # rellenar credenciales
./run.sh                  # = uv run python server.py
```

`oracledb` corre en *thin mode* — no requiere Oracle Instant Client.

## Variables de entorno

DB: `DB_SCHEME_PROD_VIEW`, `DB_HOST_PROD_VIEW`, `DB_USER_PROD_VIEW`, `DB_PASSWORD_PROD_VIEW`.
Server: `MCP_PORT` (obligatorio), `MCP_HOST` (opcional, default `0.0.0.0`).
Auth: `MCP_AUTH_TOKEN` (token compartido), `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`,
`OAUTH_REDIRECT_URIS`, `OAUTH_SIGNING_KEY`. Ver `.env.example` y `conexion_info.md`.

## Autenticación

Dos modos (cualquiera de los dos protege `/mcp`; auth activa si hay `MCP_AUTH_TOKEN` y/o `OAUTH_CLIENT_ID`):

1. **Token compartido** — `Authorization: Bearer <t>`, `X-API-Key: <t>` o `?token=<t>`.
2. **OAuth 2.1** (authorization_code + PKCE) — el server expone metadata RFC 9728/8414,
   `/register` (DCR), `/authorize`, `/token`; tokens stateless firmados HMAC-SHA256
   (access 1 h, refresh 30 d). Es lo que usan los campos *OAuth Client ID/Secret* del
   conector de Claude (`oauth.py`).

Sin credencial válida → `401` + `WWW-Authenticate: Bearer resource_metadata="…"`.

## Herramientas

| Tool | Descripción |
|------|-------------|
| `ping()` | Comprueba conectividad. |
| `describe_table(table_name)` | Columnas (tipo, longitud, nullable). |
| `list_tables(name_like=None, page=1, page_size=100)` | Tablas y vistas del usuario, paginado. |
| `run_query(sql, page=1, page_size=100)` | Ejecuta solo `SELECT` (sin `WITH`), paginado; bloquea DML y DDL. |
| `search_docs(query="", limit=20)` | Busca en la documentación del esquema (`docs/`); vacío = catálogo. Empieza aquí para saber qué tabla usar. |
| `get_table_doc(table_name)` | Markdown documentado de un objeto (acepta `"INDEX"`). |

`page_size` máx `1000`. Las tools paginadas devuelven `{ data, columns, page, total_pages, total_results, page_size }`.
Incluir `ORDER BY` en el `SELECT` para paginación estable.

**Esquema `CL` — prefijo obligatorio:** toda tabla, vista o función en los queries debe ir calificada con el esquema `CL`
— `SELECT * FROM CL.x_table` (no `FROM x_table`), `CL.mi_vista`, `CL.mi_funcion(...)`. Sin el prefijo, falla.
(`list_tables` / `describe_table` ya operan sobre `CL`.)

## Documentación del esquema (`docs/`)

`docs/` tiene un Markdown por objeto del esquema `CL` (para qué sirve, campos, tipos,
llaves, uniones) más `docs/INDEX.md` (catálogo). Lo consultan los modelos vía
`search_docs` / `get_table_doc` sin tocar Oracle. Lo genera/actualiza una **sesión de
Claude** siguiendo `PROMPT_DOCUMENTAR.md` (copiar el prompt de ahí y pegarlo en una
sesión con este MCP conectado; es reanudable). Override de la ruta: env `DB_DOCS_DIR`.

## Proceso / detener

El proceso se llama `consulta_db_mcp` (vía `setproctitle`) → visible así en `htop`/`ps`.
Detener: `pkill consulta_db_mcp` (o `pkill -f consulta_db_mcp`).

## Logs

Cada llamada a una tool se registra (tool, query en una línea, página, nº de resultados — **sin** la data).
Salida a consola **y** a `logs/consulta_db.log` (rotación: 5 MB × 5 archivos).

## Exponer con cloudflared

Ver `conexion_info.md`. URL final del conector: `https://<URL>/mcp`.
