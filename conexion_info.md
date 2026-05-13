# Conexión del MCP `consulta-db` a Claude (Add custom connector)

Hay **dos** formas de autenticarse. Elige una para el conector:

### Opción A — OAuth 2.1 (lo que pide el dialog: Client ID / Secret)

| Campo | Valor |
|-------|-------|
| **Name** | `consulta-db` |
| **Remote MCP server URL** | `https://<URL>/mcp` |
| **OAuth Client ID** | <OAUTH_CLIENT_ID> |
| **OAuth Client Secret** | <OAUTH_CLIENT_SECRET> |

Claude descubre el OAuth solo: pega un `Bearer` inexistente → recibe `401` con
`WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`
→ lee la metadata → hace el flujo *Authorization Code + PKCE* contra `/authorize` y `/token`.
La URL **no** lleva `?token=` en este modo.

(Valores en `.env`: `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`.)

### Opción B — token compartido (más simple)

| Campo | Valor |
|-------|-------|
| **Remote MCP server URL** | `https://<URL>/mcp?token=<MCP_AUTH_TOKEN>` |
| **OAuth Client ID / Secret** | *(vacío)* |

El token (`MCP_AUTH_TOKEN` en `.env`) se acepta por `Authorization: Bearer <t>`, `X-API-Key: <t>` o `?token=<t>`.

> El endpoint MCP (FastMCP streamable-http) vive en `/mcp`. En local: `http://localhost:$MCP_PORT/mcp`.

### Detalles de auth

- Auth queda **activa** si `MCP_AUTH_TOKEN` y/o `OAUTH_CLIENT_ID` están definidos en `.env`. Ambos vacíos → server sin auth (log `auth: DISABLED`).
- Endpoints OAuth servidos por el propio MCP: `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server` (RFC 9728 / 8414), `/register` (DCR, RFC 7591), `/authorize`, `/token`. Tokens stateless firmados con HMAC-SHA256 (`OAUTH_SIGNING_KEY`); access 1 h, refresh 30 d.
- `/authorize` auto-aprueba (server personal de un solo usuario): el control real es el `client_secret` en `/token` (clientes confidenciales) + PKCE S256.
- Si `OAUTH_CLIENT_ID` se deja vacío, igual hay registro dinámico de clientes (`POST /register`), pero entonces no puedes pre-pegar credenciales en el dialog.
- Rotar credenciales: editar `.env` (`MCP_AUTH_TOKEN` / `OAUTH_CLIENT_SECRET` / `OAUTH_SIGNING_KEY`), reiniciar `./run.sh`, actualizar el conector. Cambiar `OAUTH_SIGNING_KEY` invalida todos los tokens emitidos.
- **cloudflared** debe pasar `Host` y `X-Forwarded-Proto: https` (lo hace por defecto) para que las URLs en la metadata salgan con el dominio https correcto.

## Cómo se levanta

1. `uv sync` (crea `.venv` e instala deps).
2. `cp .env.example .env` y rellenar variables Oracle (`DB_SCHEME_PROD_VIEW`,
   `DB_HOST_PROD_VIEW`, `DB_USER_PROD_VIEW`, `DB_PASSWORD_PROD_VIEW`) y
   `MCP_PORT` (obligatorio; `MCP_HOST` opcional, default `0.0.0.0`).
3. `./run.sh` (= `uv run python server.py`) → escucha en `$MCP_HOST:$MCP_PORT`.
3. Túnel de Cloudflare apuntando el subdominio al puerto local:

   ```bash
   # rápido / efímero:
   cloudflared tunnel --url http://localhost:$MCP_PORT

   # o con túnel con nombre + DNS fijo:
   cloudflared tunnel create consulta-db
   cloudflared tunnel route dns consulta-db <URL>
   # config.yml:
   #   tunnel: consulta-db
   #   credentials-file: /home/ojitos369/.cloudflared/<UUID>.json
   #   ingress:
   #     - hostname: <URL>
   #       service: http://localhost:$MCP_PORT
   #     - service: http_status:404
   cloudflared tunnel run consulta-db
   ```

> Nota: el guion bajo en `<URL>` es válido en DNS pero algunos
> validadores de hostname lo rechazan; si Cloudflare se queja, usar `<URL>`.

## Variables de entorno (credenciales Oracle)

| Variable | Significado |
|----------|-------------|
| `DB_SCHEME_PROD_VIEW` | service name / SID de Oracle |
| `DB_HOST_PROD_VIEW` | host, o `host:puerto` (puerto por defecto `1521`) |
| `DB_USER_PROD_VIEW` | usuario |
| `DB_PASSWORD_PROD_VIEW` | contraseña |

## Variables de entorno (servidor MCP)

| Variable | Significado |
|----------|-------------|
| `MCP_PORT` | **obligatorio** — puerto donde escucha el MCP (sin default) |
| `MCP_HOST` | opcional — interfaz de escucha (default `0.0.0.0`) |

## Herramientas que expone el MCP

- `ping()` — comprueba conectividad (hora y versión del cliente).
- `describe_table(table_name)` — columnas de una tabla/vista.
- `list_tables(name_like=None, page=1, page_size=100)` — tablas y vistas visibles, paginado.
- `run_query(sql, page=1, page_size=100)` — ejecuta **solo** `SELECT` (bloquea DML/DDL y CTE/`WITH`), paginado.
- `search_docs(query="", limit=20)` — busca en la documentación del esquema (`docs/`); vacío = catálogo.
- `get_table_doc(table_name)` — Markdown documentado de un objeto (acepta `"INDEX"`).

> La doc de `docs/` (un `.md` por objeto + `INDEX.md`) la mantiene una sesión de Claude
> siguiendo `PROMPT_DOCUMENTAR.md`. Ver `README.md` › "Documentación del esquema".

`page_size` máx `1000`. `run_query` y `list_tables` devuelven:

```json
{
  "data": [ /* lista de objetos (filas) */ ],
  "columns": ["COL1", "COL2"],
  "page": 1,
  "total_pages": 42,
  "total_results": 4123,
  "page_size": 100
}
```

Para paginación estable incluir `ORDER BY` en el `SELECT` (Oracle no garantiza orden entre páginas sin él). La consulta se envuelve en subquery + `OFFSET ... ROWS FETCH NEXT ... ROWS ONLY`, por eso `WITH` no se soporta en `run_query`.

### Esquema `CL` — prefijo OBLIGATORIO

El esquema de la base de datos es **`CL`**. Todo nombre de **tabla, vista o función** en los queries debe ir calificado con él:

- ✅ `SELECT * FROM CL.x_table`   ·   ❌ `SELECT * FROM x_table`
- ✅ `SELECT * FROM CL.mi_vista`
- ✅ `SELECT CL.mi_funcion(col) FROM CL.x_table`

Sin el prefijo `CL.` el query falla. (Oracle es case-insensitive para identificadores sin comillas → `cl.` también vale.)
`list_tables` y `describe_table` ya operan sobre el esquema `CL`; a `describe_table` puedes pasarle el nombre con o sin `CL.`.
