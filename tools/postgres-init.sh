#!/bin/sh
set -eu

if [ "${AEGIS_POSTGRES_RUNTIME_PASSWORD:-}" = "" ] \
    || [ "${AEGIS_POSTGRES_RUNTIME_PASSWORD}" = "change-me-before-use" ]; then
    echo "AEGIS_POSTGRES_RUNTIME_PASSWORD must be set" >&2
    exit 1
fi

psql --set=ON_ERROR_STOP=1 \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" \
    --file /opt/aegis/migrations/0001_layer2.sql

psql --set=ON_ERROR_STOP=1 \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" \
    --file /opt/aegis/migrations/0002_layer3.sql

psql --set=ON_ERROR_STOP=1 \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" \
    --file /opt/aegis/migrations/0003_layer4.sql

psql --set=ON_ERROR_STOP=1 \
    --set=runtime_password="${AEGIS_POSTGRES_RUNTIME_PASSWORD}" \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" <<'SQL'
SELECT 'CREATE ROLE aegis_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app')
\gexec
ALTER ROLE aegis_app
    NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION NOBYPASSRLS
    PASSWORD :'runtime_password';
GRANT aegis_runtime TO aegis_app;
SQL
