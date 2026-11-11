#!/bin/bash
set -Eeuo pipefail
umask 077
export PGDATA=/var/lib/postgresql/18/docker
readonly credentials=/run/asservat/postgres-private
readonly work=/run/asservat/postgres
readonly repository=/var/lib/pgbackrest
fail() { echo 'bundled PostgreSQL unavailable: check retained state, storage and backup status' >&2; exit 1; }
[[ ${PGHOST:-} =~ ^[a-z0-9-]+\.[a-z0-9-]+\.svc$ ]] || fail
[[ ${PGMAXCONNECTIONS:-} == 117 || ${PGMAXCONNECTIONS:-} == 122 ]] || fail
[[ ${KEYCLOAK_DATABASE:-} == true || ${KEYCLOAK_DATABASE:-} == false ]] || fail
[[ $KEYCLOAK_DATABASE == true && $PGMAXCONNECTIONS == 122 || $KEYCLOAK_DATABASE == false && $PGMAXCONNECTIONS == 117 ]] || fail
mkdir -p "$work"
files=(ca.crt)
if [[ ${1:-} == server ]]; then files+=(server.crt server.key); fi
for file in "${files[@]}"; do
    [[ -f $credentials/$file && ! -L $work/$file ]] || fail
    cp "$credentials/$file" "$work/$file"
done
cp "$credentials/backup.pgpass" "$work/backup.pgpass"
chmod 0600 "$work/backup.pgpass"
if [[ ${1:-} == server ]]; then chmod 0600 "$work/server.key"; fi
cat > "$work/pgbackrest.conf" <<EOF
[asservat]
pg1-path=$PGDATA
pg1-user=asservat_backup
pg1-database=postgres
pg1-port=5432
[global]
repo1-path=$repository
repo1-cipher-type=aes-256-cbc
repo1-cipher-pass=$(cat "$credentials/backup-cipher")
repo1-retention-full=2
repo1-retention-diff=2
process-max=1
start-fast=y
archive-async=n
archive-timeout=60
log-level-console=warn
log-level-file=off
lock-path=$work/locks
EOF
# libpq transport is TLS even for a backup running in the same Pod. No remote
# pgBackRest server or SSH daemon is needed with both PVCs mounted locally.
export PGSSLMODE=verify-full PGSSLROOTCERT="$work/ca.crt" PGPASSFILE="$work/backup.pgpass"
case ${1:-} in
server)
    mkdir -p "$PGDATA" "$repository"
    if [[ ! -s $PGDATA/PG_VERSION ]]; then
        [[ -z $(find "$PGDATA" -mindepth 1 -maxdepth 1 -print -quit) ]] || fail
        initdb --username=asservat_admin --pwfile="$credentials/administrator-password" \
            --auth-local=scram-sha-256 --auth-host=scram-sha-256 --encoding=UTF8 --data-checksums >/dev/null 2>&1 || fail
        # Initial administration uses only a private Unix socket and a temporary
        # local rule. No TCP listener exists before roles and ownership are set.
        echo 'local all all trust' > "$work/initial_hba.conf"
        trap 'pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null 2>&1 || true' EXIT
        pg_ctl -D "$PGDATA" -o "-c listen_addresses='' -c unix_socket_directories=$work -c ssl=off -c hba_file=$work/initial_hba.conf" -w start >/dev/null 2>&1 || fail
        psql --no-psqlrc -X --set=ON_ERROR_STOP=1 --host="$work" --username=asservat_admin --dbname=postgres \
            --set=ddl_verifier="$(cat "$credentials/ddl-verifier")" --set=backup_verifier="$(cat "$credentials/backup-verifier")" <<'SQL' >/dev/null 2>&1 || fail
CREATE ROLE asservat_ddl LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 1 PASSWORD :'ddl_verifier';
CREATE ROLE asservat_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD :'backup_verifier';
CREATE DATABASE asservat OWNER asservat_ddl;
GRANT CONNECT ON DATABASE postgres TO asservat_backup;
GRANT pg_read_all_settings TO asservat_backup;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_backup_start(text,boolean) TO asservat_backup;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_backup_stop(boolean) TO asservat_backup;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_switch_wal() TO asservat_backup;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_create_restore_point(text) TO asservat_backup;
SQL
        if [[ $KEYCLOAK_DATABASE == true ]]; then
            psql --no-psqlrc -X --set=ON_ERROR_STOP=1 --host="$work" --username=asservat_admin --dbname=postgres \
                --set=keycloak_verifier="$(cat "$credentials/keycloak-verifier")" <<'SQL' >/dev/null 2>&1 || fail
CREATE ROLE keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5 PASSWORD :'keycloak_verifier';
CREATE DATABASE keycloak OWNER keycloak;
REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
SQL
        fi
        pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null 2>&1 || fail
        trap - EXIT
        touch "$PGDATA/asservat-initialized"
    fi
    [[ $(cat "$PGDATA/PG_VERSION") == 18 && -f $PGDATA/asservat-initialized ]] || fail
    exec postgres -D "$PGDATA" -c config_file=/etc/asservat/postgresql.conf -c max_connections="$PGMAXCONNECTIONS"
    ;;
backup)
    # One joined scheduler in the database Pod. Failed backup/check never claims
    # healthy recovery. Synchronous archive-push never discards required WAL.
    child=''
    trap '[[ -z $child ]] || kill "$child" 2>/dev/null || true; [[ -z $child ]] || wait "$child" 2>/dev/null || true; exit 0' TERM INT
    run() { "$@" & child=$!; local code=0; wait "$child" || code=$?; child=''; return "$code"; }
    until [[ -f $PGDATA/asservat-initialized ]] && pg_isready -h "$PGHOST" -U asservat_backup -d postgres >/dev/null 2>&1; do
        sleep 2 & child=$!; wait "$child"; child=''
    done
    run timeout --signal=TERM --kill-after=10s 300 pgbackrest --config="$work/pgbackrest.conf" --stanza=asservat stanza-create
    while true; do
        if run timeout --signal=TERM --kill-after=10s 120 pgbackrest --config="$work/pgbackrest.conf" --stanza=asservat check && run timeout --signal=TERM --kill-after=10s 21600 pgbackrest --config="$work/pgbackrest.conf" --stanza=asservat --type=full backup; then
            date -u +%s > "$repository/last-success"
        else
            echo 'bundled PostgreSQL backup unavailable' >&2
            rm -f "$repository/last-success"
        fi
        sleep 86400 & child=$!; wait "$child"; child=''
    done
    ;;
*) fail ;;
esac
