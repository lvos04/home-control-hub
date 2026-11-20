#!/usr/bin/env bash
# Elke job heeft een eigen cluster en Unix-socket. De runner deelt zijn netwerk met andere jobs.
set -euo pipefail
pgbin=/usr/lib/postgresql/16/bin
basis="$RUNNER_TEMP/hch-postgres"
case "$1" in
  start)
    if [[ ! -x "$pgbin/initdb" ]]; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y --no-install-recommends postgresql-common
      # Het distributiepakket hoeft geen cluster op een vaste TCP-poort te starten.
      echo 'create_main_cluster = false' >> /etc/postgresql-common/createcluster.conf
      apt-get install -y --no-install-recommends postgresql-16
    fi
    install -d -m 700 -o postgres -g postgres "$basis"
    runuser -u postgres -- "$pgbin/initdb" -D "$basis/data" --auth-local=trust --auth-host=reject --locale=C.UTF-8
    runuser -u postgres -- "$pgbin/pg_ctl" -D "$basis/data" -l "$basis/server.log" \
      -o "-c listen_addresses='' -k '$basis'" -w start
    PGHOST="$basis" psql -U postgres -Atc 'SHOW server_version'
    echo "PGHOST=$basis" >> "$GITHUB_ENV"
    ;;
  stop)
    if [[ -f "$basis/data/postmaster.pid" ]]; then
      runuser -u postgres -- "$pgbin/pg_ctl" -D "$basis/data" -m fast -w stop
    fi
    rm -rf -- "$basis"
    ;;
  *) exit 2 ;;
esac
