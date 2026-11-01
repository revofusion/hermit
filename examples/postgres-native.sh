#!/bin/sh
set -eu
export PATH=/usr/lib/postgresql/17/bin:/usr/bin:/bin
work=/tmp/hermit-pg-native-smoke
mkdir "$work"
cleanup() {
  pg_ctl -D "$work/data" -m immediate stop >/dev/null 2>&1 || :
  rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM
cp -a /var/lib/hermit-postgres/seed "$work/data"
cat >> "$work/data/postgresql.conf" <<EOF
shared_memory_type = mmap
dynamic_shared_memory_type = mmap
shared_buffers = '8MB'
max_connections = 10
max_worker_processes = 0
max_parallel_workers = 0
autovacuum = off
huge_pages = off
listen_addresses = ''
unix_socket_directories = '$work'
jit = off
EOF
pg_ctl -D "$work/data" -l "$work/server.log" -w -t 30 start || { cat "$work/server.log"; exit 1; }
export PGHOST="$work" PGUSER=postgres PGDATABASE=postgres
psql -X -v ON_ERROR_STOP=1 -q -c 'CREATE TABLE hermit_smoke (id integer PRIMARY KEY, value integer NOT NULL); INSERT INTO hermit_smoke VALUES (1, 0), (2, 0);'
psql -X -v ON_ERROR_STOP=1 -q -c 'BEGIN; UPDATE hermit_smoke SET value = value + 7 WHERE id = 1; COMMIT;' &
a=$!
psql -X -v ON_ERROR_STOP=1 -q -c 'BEGIN; UPDATE hermit_smoke SET value = value + 11 WHERE id = 2; COMMIT;' &
b=$!
wait "$a"
wait "$b"
test "$(psql -X -Atq -v ON_ERROR_STOP=1 -c 'SELECT sum(value) FROM hermit_smoke')" = 18
if postgres -D "$work/data" >"$work/duplicate.log" 2>&1; then
  echo 'duplicate server unexpectedly started' >&2
  exit 1
fi
grep -q 'lock file "postmaster.pid" already exists' "$work/duplicate.log"
pg_ctl -D "$work/data" -m fast -w -t 30 stop
pg_ctl -D "$work/data" -l "$work/server.log" -w -t 30 start || { cat "$work/server.log"; exit 1; }
test "$(psql -X -Atq -v ON_ERROR_STOP=1 -c 'SELECT string_agg(id::text || chr(58) || value::text, chr(44) ORDER BY id) FROM hermit_smoke')" = '1:7,2:11'
pg_ctl -D "$work/data" -m fast -w -t 30 stop
echo 'postgres-native startup=ok concurrent-transactions=ok duplicate-lock=ok shutdown=ok restart-persistence=ok'
