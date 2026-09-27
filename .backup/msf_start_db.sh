#!/bin/bash
# ==============================================================================
# Ruadan - PostgreSQL + banco do Metasploit em container (SEM systemd)
# ==============================================================================
# Uso: msf_start_db.sh
#
# POR QUE NÃO USAR `msfdb init`: ele NÃO é idempotente. Quando executado uma
# 2ª vez (o Ruadan dispara esta fase uma vez por key do nmap_dict — hostname e
# IP do mesmo alvo), ele regenera o database.yml com senha NOVA sem atualizar
# o role já existente no postgres → "password authentication failed" → o
# msfconsole fica "Database not connected" para sempre.
# Este script provisiona TUDO manualmente de forma idempotente:
#   1. PostgreSQL via init SysV (service postgresql start)
#   2. Role 'msf' com senha fixa (ALTER se existir, CREATE se não)
#   3. Database 'msf' (createdb apenas se não existir)
#   4. database.yml SEMPRE regenerado e consistente com o role
#   5. Schema do MSF via rake db:migrate (apenas se a tabela 'hosts' faltar)
# Execuções repetidas convergem para o MESMO estado consistente.
# ==============================================================================
set -u

DB_USER="${MSF_DB_USER:-msf}"
DB_PASS="${MSF_DB_PASS:-msf}"
DB_NAME="${MSF_DB_NAME:-msf}"
MSF_DIR="/usr/share/metasploit-framework"
MSF_DB_YML="${MSF_DIR}/config/database.yml"

log() { echo "[msf_start_db] $*"; }

# ----------------------------------------------------------------------------
# 1. PostgreSQL (container não tem systemd — usar init script SysV)
# ----------------------------------------------------------------------------
log "Iniciando PostgreSQL via init script SysV..."
service postgresql start 2>&1 || true

PG_READY=0
for _i in $(seq 1 15); do
    if command -v pg_isready >/dev/null 2>&1 && pg_isready -q 2>/dev/null; then
        PG_READY=1
        log "PostgreSQL pronto (pg_isready OK)."
        break
    fi
    sleep 1
done
if [ "$PG_READY" -eq 0 ]; then
    log "[ERRO] PostgreSQL não respondeu em 15s. Tentando pg_ctlcluster..."
    for _clus in $(ls /etc/postgresql/ 2>/dev/null); do
        for _ver in $(ls "/etc/postgresql/$_clus" 2>/dev/null); do
            pg_ctlcluster "$_clus" "$_ver" start 2>&1 || true
        done
    done
    sleep 3
    pg_isready 2>&1 || log "[ERRO] PostgreSQL continua fora."
fi

# ----------------------------------------------------------------------------
# 2. Role 'msf' — idempotente de verdade (senha SEMPRE resetada para a fixa)
# ----------------------------------------------------------------------------
if su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'\"" 2>/dev/null | grep -q 1; then
    log "Role '${DB_USER}' existe — resetando senha para manter consistência com o database.yml..."
    su postgres -c "psql -c \"ALTER ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';\"" >/dev/null 2>&1 || true
else
    log "Criando role '${DB_USER}'..."
    su postgres -c "psql -c \"CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';\"" >/dev/null 2>&1 || true
fi

# ----------------------------------------------------------------------------
# 3. Database 'msf' — criar apenas se não existir
# ----------------------------------------------------------------------------
if su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'\"" 2>/dev/null | grep -q 1; then
    log "Database '${DB_NAME}' já existe."
else
    log "Criando database '${DB_NAME}' (owner: ${DB_USER})..."
    su postgres -c "createdb -O ${DB_USER} ${DB_NAME}" 2>&1 || true
fi

# ----------------------------------------------------------------------------
# 4. database.yml — SEMPRE regenerado (garante yml<->role consistentes)
# ----------------------------------------------------------------------------
log "Gerando ${MSF_DB_YML} (consistente com o role)..."
mkdir -p "$(dirname "${MSF_DB_YML}")"
cat > "${MSF_DB_YML}" <<_EOF_
production:
  adapter: postgresql
  database: ${DB_NAME}
  username: ${DB_USER}
  password: ${DB_PASS}
  host: 127.0.0.1
  port: 5432
  pool: 75
  timeout: 5
_EOF_

# ----------------------------------------------------------------------------
# 5. Schema do MSF — rake db:migrate apenas se a tabela 'hosts' não existir
# ----------------------------------------------------------------------------
if PGPASSWORD="${DB_PASS}" psql -h 127.0.0.1 -U "${DB_USER}" -d "${DB_NAME}" -tAc "SELECT to_regclass('public.hosts')" 2>/dev/null | grep -q hosts; then
    log "Schema do MSF já aplicado (tabela 'hosts' presente)."
else
    log "Aplicando schema do MSF (rake db:migrate) — pode demorar ~1-2min na 1ª vez..."
    cd "${MSF_DIR}" 2>/dev/null && RAILS_ENV=production bundle exec rake db:migrate 2>&1 | tail -3 || \
        log "[AVISO] rake db:migrate falhou — o msfconsole pode conectar sem schema."
fi

# ----------------------------------------------------------------------------
# Verificação final
# ----------------------------------------------------------------------------
log "Verificação final:"
pg_isready 2>&1 || true
if PGPASSWORD="${DB_PASS}" psql -h 127.0.0.1 -U "${DB_USER}" -d "${DB_NAME}" -tAc "SELECT 1" >/dev/null 2>&1; then
    log "[OK] Conexão '${DB_USER}@${DB_NAME}' validada."
else
    log "[ERRO] Não foi possível conectar com ${DB_USER}/${DB_NAME}."
fi
exit 0
