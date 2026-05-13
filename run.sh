#!/usr/bin/env bash
# Arranca el MCP "consulta_db" en local en el puerto 8381 (con uv).
set -euo pipefail
cd "$(dirname "$0")"

# Carga variables de entorno desde .env si existe.
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

: "${DB_SCHEME_PROD_VIEW:?falta DB_SCHEME_PROD_VIEW}"
: "${DB_HOST_PROD_VIEW:?falta DB_HOST_PROD_VIEW}"
: "${DB_USER_PROD_VIEW:?falta DB_USER_PROD_VIEW}"
: "${DB_PASSWORD_PROD_VIEW:?falta DB_PASSWORD_PROD_VIEW}"
: "${MCP_PORT:?falta MCP_PORT}"

exec uv run python server.py
