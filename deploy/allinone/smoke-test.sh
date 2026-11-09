#!/usr/bin/env bash
# Rooktest van de alles-in-één image (ALLEEN ontwikkeling/CI; geen installatiemethode).
#   deploy/allinone/smoke-test.sh [image]   (standaard home-control-hub:dev)
# Controleert: start als root → processen als 568, healthcheck 'healthy', /healthz, /readyz, statuspagina
# 'niet gekoppeld', geheimen 0600/568 en blijvend na herstart, herstel na harde kill, start als 568, duidelijke fout
# bij verkeerde maprechten.
set -euo pipefail

IMAGE="${1:-home-control-hub:dev}"
WORK="$(mktemp -d)"
NAME="hch-smoke-$$"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
PASS=0
FAIL=0

cleanup() {
  docker rm -f "$NAME" "$NAME-568" "$NAME-bad" >/dev/null 2>&1 || true
  docker run --rm -v "$WORK:/w" --entrypoint sh "$IMAGE" -c 'rm -rf /w/* /w/.[!.]* 2>/dev/null || true' >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

ok() { echo "OK   $*"; PASS=$((PASS + 1)); }
nok() { echo "FOUT $*"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then ok "$1"; else nok "$1"; fi; }

wait_healthy() {
  local c="$1" i
  for i in $(seq 1 60); do
    case "$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null || echo weg)" in
      healthy) return 0 ;;
      weg) return 1 ;;
    esac
    sleep 3
  done
  docker logs "$c" | tail -30
  return 1
}

# zonder pipes (pipefail + grep -q geeft anders vals-negatieve SIGPIPE-fouten)
http_has() { curl -fsS "http://127.0.0.1:$PORT$1" -o "$WORK/http.txt" && grep -q -- "$2" "$WORK/http.txt"; }
log_has() { docker logs "$1" > "$WORK/log.txt" 2>&1; grep -q -- "$2" "$WORK/log.txt"; }

run() { # naam, datamap, extra args
  local n="$1" d="$2"; shift 2
  docker run -d --name "$n" -p "127.0.0.1:$PORT:30420" -v "$d:/appdata" \
    --security-opt no-new-privileges:true --health-interval 3s --health-start-period 60s "$@" "$IMAGE" >/dev/null
}

mkdir -p "$WORK/root" "$WORK/u568" "$WORK/bad"

echo "== 1. start als root op een root-eigendom-map (zoals een verse TrueNAS-dataset)"
run "$NAME" "$WORK/root"
check "healthcheck wordt healthy" "wait_healthy $NAME"
check "/healthz geeft 200" "http_has /healthz '\"status\":\"ok\"'"
check "/readyz geeft ready" "http_has /readyz '\"ready\"'"
check "statuspagina toont 'niet gekoppeld'" "http_has / 'niet gekoppeld'"
check "API zonder token geeft 401 unauthorized" \
  "[ \"\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/connector/v1/discover)\" = 401 ]"
docker top "$NAME" -eo pid,user,args > "$WORK/ps.txt"
check "procestabel is leesbaar" "[ \"\$(wc -l < $WORK/ps.txt)\" -ge 5 ]"
check "geen proces draait als root (behalve init/bewaker)" \
  "[ -z \"\$(awk 'NR>1 && \$2!=\"568\" && \$2!=\"apps\" && \$0 !~ /dumb-init|supervisor.py/' $WORK/ps.txt)\" ]"
check "postgres, api en worker draaien als 568" \
  "[ \"\$(awk '(\$2==\"568\" || \$2==\"apps\") && /postgres -D|integrations api|integrations worker/' $WORK/ps.txt | wc -l)\" -ge 3 ]"
check "geen netwerkpoort voor PostgreSQL (alleen unix-socket)" \
  "! docker exec $NAME python -c 'import socket;s=socket.socket();s.settimeout(1);s.connect((\"127.0.0.1\",5432))' 2>/dev/null"
check "geheimen 0600 en eigenaar 568" \
  "[ \"\$(stat -c '%a %u' $WORK/root/secrets/vault.key)\" = '600 568' ] && [ \"\$(stat -c '%a %u' $WORK/root/secrets/identity.ed25519)\" = '600 568' ]"
check "ontkoppelcode staat in de app-log" "log_has $NAME 'Lokale ontkoppelcode'"
check "geen setuid/setgid-bestanden in de image" \
  "[ -z \"\$(docker exec $NAME sh -c 'find / -xdev -perm /6000 -type f 2>/dev/null')\" ]"
SUM1="$(sha256sum "$WORK/root/secrets/vault.key" | cut -d' ' -f1)"

echo "== 2. herstart: data en geheimen blijven"
docker restart "$NAME" >/dev/null
check "na herstart weer healthy" "wait_healthy $NAME"
check "vault.key ongewijzigd na herstart" "[ \"\$(sha256sum $WORK/root/secrets/vault.key | cut -d' ' -f1)\" = '$SUM1' ]"

echo "== 3. harde kill (stroomuitval) en opnieuw starten"
docker kill "$NAME" >/dev/null
docker start "$NAME" >/dev/null
check "na harde kill weer healthy" "wait_healthy $NAME"
docker rm -f "$NAME" >/dev/null

echo "== 4. start direct als 568 op een 568-map"
docker run --rm -v "$WORK:/w" --entrypoint sh "$IMAGE" -c 'chown 568:568 /w/u568' >/dev/null
run "$NAME-568" "$WORK/u568" --user 568:568
check "als 568 gestart en healthy" "wait_healthy $NAME-568"
docker rm -f "$NAME-568" >/dev/null

echo "== 5. verkeerde rechten geven een duidelijke Nederlandse fout"
docker run -d --name "$NAME-bad" -v "$WORK/bad:/appdata" --user 1000:1000 "$IMAGE" >/dev/null
sleep 8
check "fout 'geen schrijfrechten' in de log" "log_has $NAME-bad 'FOUT: geen schrijfrechten'"

echo
echo "Resultaat: $PASS geslaagd, $FAIL mislukt"
[ "$FAIL" -eq 0 ]
