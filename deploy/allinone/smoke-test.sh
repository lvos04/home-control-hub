#!/usr/bin/env bash
# Rooktest van de alles-in-één image (ALLEEN ontwikkeling/CI; geen installatiemethode).
#   deploy/allinone/smoke-test.sh [image]   (standaard home-control-hub:dev)
# Controleert: start als root → ELK proces (ook PID 1) Uid 568, CapEff 0 en NoNewPrivs 1, zombies worden door PID 1
# opgeruimd, healthcheck 'healthy', /healthz, /readyz, statuspagina in Peil ('Niet gekoppeld' met koppelformulier,
# eerste signaal niet groen), geheimen 0600/568 en blijvend na herstart, databasegegevens blijvend na herstart én
# harde kill, start als 568 (Custom User), duidelijke fout bij verkeerde maprechten, te grote verzoeken geweigerd
# (413, ook chunked).
# De containers draaien zoals het standaard TrueNAS Custom App-formulier (ix-app): ZONDER --security-opt
# no-new-privileges en ZONDER --cap-drop, dus met de standaard Docker-capabilities (contract 1.2 §2.2, A6).
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
  local c="$1"
  for _ in $(seq 1 60); do
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
http_has_401_reason() {
  curl -s "http://127.0.0.1:$PORT/connector/v1/discover" -o "$WORK/http.txt" && grep -q '"reason":"not_linked"' "$WORK/http.txt"
}
log_has() { docker logs "$1" > "$WORK/log.txt" 2>&1; grep -q -- "$2" "$WORK/log.txt"; }

run() { # naam, datamap, extra args — bewust geen --security-opt en geen --cap-drop (zoals het formulier)
  local n="$1" d="$2"; shift 2
  docker run -d --name "$n" -p "127.0.0.1:$PORT:30420" -v "$d:/appdata" \
    --health-interval 3s --health-start-period 60s "$@" "$IMAGE" >/dev/null
}
# Elk proces in de container (behalve deze controle zelf en Dockers kortlevende healthcheck-exec, die als eerste naar
# 568 wisselt): Uid 568 (alle vier velden), CapEff 0000000000000000 en NoNewPrivs 1. Schrijft afwijkingen naar stdout.
PROC_CHECK='
import os
me = os.getpid()
bad, seen = [], 0
for p in sorted(int(x) for x in os.listdir("/proc") if x.isdigit()):
    if p == me:
        continue
    try:
        st = dict(l.split(":", 1) for l in open(f"/proc/{p}/status").read().splitlines() if ":" in l)
        cmd = open(f"/proc/{p}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace").strip()
    except OSError:
        continue
    if "healthcheck.py" in cmd or st.get("State", "").strip().startswith("Z"):
        continue
    seen += 1
    uids = st["Uid"].split()
    capeff = st["CapEff"].strip()
    nnp = st.get("NoNewPrivs", "?").strip()
    if uids != ["568"] * 4 or capeff != "0" * 16 or nnp != "1":
        bad.append(f"{p} uid={uids} capeff={capeff} nnp={nnp} cmd={cmd[:60]}")
print("\n".join(bad) if bad else f"OK {seen}")
'
procs_ok() { # container
  local out
  out="$(docker exec -u 568:568 "$1" python -c "$PROC_CHECK" 2>&1)"
  echo "$out" > "$WORK/procs.txt"
  case "$out" in OK*) [ "${out#OK }" -ge 4 ] ;; *) cat "$WORK/procs.txt"; return 1 ;; esac
}
pid1_is_supervisor_568() {
  [ "$(docker exec -u 568:568 "$1" sh -c 'tr "\0" " " < /proc/1/cmdline; echo; awk "/^Uid:/{print \$2}" /proc/1/status' | tr '\n' '|')" \
    = "python /usr/local/lib/hch/supervisor.py |568|" ]
}
zombies_reaped() { # verweesd proces dat als zombie bij PID 1 terechtkomt, moet binnen enkele seconden weg zijn
  docker exec -u 568:568 "$1" python -c 'import os,time
pid = os.fork()
if pid == 0:
    os._exit(0)
time.sleep(0.3)' >/dev/null
  sleep 5
  [ -z "$(docker exec -u 568:568 "$1" sh -c 'for s in /proc/[0-9]*/stat; do awk "\$3==\"Z\"" "$s" 2>/dev/null; done')" ]
}
healthcheck_drops_root() { # de healthcheck-exec (als root gestart door Docker) wisselt eerst naar 568 + no-new-privs
  [ "$(docker exec "$1" python -c 'exec(open("/usr/local/lib/hch/healthcheck.py").read().split("port = ")[0])
import os
st = dict(l.split(":", 1) for l in open("/proc/self/status").read().splitlines() if ":" in l)
print(os.getuid(), st["CapEff"].strip(), st["NoNewPrivs"].strip())')" = "568 0000000000000000 1" ]
}
# Bestanden in de datamap bekijken via een wegwerpcontainer (als root in de container): de datamap is van 568 met
# 0700/0600, dus een gewone hostgebruiker (zoals de CI-runner) kan ze zelf niet lezen.
in_work() { docker run --rm --network none -v "$WORK:/w" --entrypoint sh "$IMAGE" -c "$1"; }
# SQL in de ingebouwde database (als 568, via de unix-socket; alleen voor deze test)
sql() { docker exec --user 568:568 "$1" psql -h /tmp/hch-pg -U hch -d hch -tAc "$2"; }
marker_write() {
  [ "$(sql "$NAME" "INSERT INTO service_state (key, value, updated_at) VALUES ('rooktest', '{}'::jsonb, now()) RETURNING key" | head -1)" = rooktest ]
}
marker_present() { [ "$(sql "$NAME" "SELECT count(*) FROM service_state WHERE key='rooktest'")" = 1 ]; }
pg_dump_works() { # zonder werkende pg_dump weigert elke latere update te migreren (back-up vooraf is verplicht)
  docker exec --user 568:568 "$NAME" sh -c 'pg_dump -Fc -h /tmp/hch-pg -U hch -f /tmp/rooktest.dump hch && test -s /tmp/rooktest.dump && rm -f /tmp/rooktest.dump'
}
too_large() { # > 1 MiB zonder token: de grens geldt vóór de authenticatie
  [ "$(head -c 1100000 /dev/zero | curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
    --data-binary @- "http://127.0.0.1:$PORT/integrations/v1/sso/recovery/accounts")" = 413 ]
}
too_large_chunked() { # zelfde grens zonder Content-Length (chunked), op de ontkoppelroute
  [ "$(head -c 1100000 /dev/zero | curl -s -o /dev/null -w '%{http_code}' -H 'Transfer-Encoding: chunked' \
    -H 'Content-Type: application/json' --data-binary @- "http://127.0.0.1:$PORT/connector/v1/hub-link/unlink")" = 413 ]
}

mkdir -p "$WORK/root" "$WORK/u568" "$WORK/bad"

echo "== 1. start als root op een root-eigendom-map (zoals een verse TrueNAS-dataset)"
run "$NAME" "$WORK/root"
check "healthcheck wordt healthy" "wait_healthy $NAME"
check "/healthz geeft 200" "http_has /healthz '\"status\":\"ok\"'"
check "/readyz geeft ready" "http_has /readyz '\"ready\"'"
check "statuspagina (Peil) toont 'Niet gekoppeld' met koppelformulier en vingerafdrukveld" \
  "http_has / 'Peil statuspagina-sjabloon 1.1.0' && http_has / 'Niet gekoppeld' && http_has / 'name=\"hub_vingerafdruk\"'"
check "statuspagina: eerste signaal niet groen zolang niet gekoppeld" "http_has / 'pil pil-onbekend\"><svg aria-hidden=\"true\"><use href=\"#i-onbekend\"/></svg>Niet gereed'"
check "API zonder token geeft 401 unauthorized (not_linked)" \
  "[ \"\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/connector/v1/discover)\" = 401 ] && http_has_401_reason"
check "elk proces: Uid 568, CapEff 0, NoNewPrivs 1 (ook PID 1)" "procs_ok $NAME"
check "PID 1 is de bewaker en draait als 568" "pid1_is_supervisor_568 $NAME"
check "verweesde zombies worden door PID 1 opgeruimd" "zombies_reaped $NAME"
check "healthcheck-exec wisselt naar 568 zonder capabilities" "healthcheck_drops_root $NAME"
check "postgres, api en worker draaien" \
  "docker top $NAME -eo pid,user,args > $WORK/ps.txt && [ \"\$(grep -cE 'postgres -D|integrations api|integrations worker' $WORK/ps.txt)\" -ge 3 ]"
check "geen netwerkpoort voor PostgreSQL (alleen unix-socket)" \
  "! docker exec $NAME python -c 'import socket;s=socket.socket();s.settimeout(1);s.connect((\"127.0.0.1\",5432))' 2>/dev/null"
check "geheimen 0600 en eigenaar 568" \
  "[ \"\$(in_work 'stat -c \"%a %u\" /w/root/secrets/vault.key /w/root/secrets/identity.ed25519' | sort -u)\" = '600 568' ]"
check "geen lokale ontkoppelcode meer (contract 1.2 §3.7)" "! log_has $NAME 'ontkoppelcode'"
check "no-new-privileges staat in de app-log" "log_has $NAME 'no-new-privileges aan'"
check "geen setuid/setgid-bestanden in de image" \
  "[ -z \"\$(docker exec $NAME sh -c 'find / -xdev -perm /6000 -type f 2>/dev/null')\" ]"
check "te groot verzoek zonder login geeft 413" too_large
check "te groot chunked verzoek geeft 413 vóór auth" too_large_chunked
check "markeerrij in de database geschreven" marker_write
check "pg_dump werkt in de image (back-up vóór migratie)" pg_dump_works
SUM1="$(in_work 'sha256sum /w/root/secrets/vault.key' | cut -d' ' -f1)"
check "vault.key leesbaar voor de controle" "[ -n '$SUM1' ]"

echo "== 2. herstart: data en geheimen blijven"
docker restart "$NAME" >/dev/null
check "na herstart weer healthy" "wait_healthy $NAME"
check "vault.key ongewijzigd na herstart" \
  "[ \"\$(in_work 'sha256sum /w/root/secrets/vault.key' | cut -d' ' -f1)\" = '$SUM1' ]"
check "databasegegevens behouden na herstart" marker_present

echo "== 3. harde kill (stroomuitval) en opnieuw starten"
docker kill "$NAME" >/dev/null
docker start "$NAME" >/dev/null
check "na harde kill weer healthy" "wait_healthy $NAME"
check "databasegegevens behouden na harde kill" marker_present
check "geen back-up nodig zonder openstaande migratie" \
  "[ \"\$(in_work 'echo leeg; ls -A /w/root/backups 2>/dev/null')\" = leeg ]"
docker rm -f "$NAME" >/dev/null

echo "== 4. start direct als 568 op een 568-map"
docker run --rm -v "$WORK:/w" --entrypoint sh "$IMAGE" -c 'chown 568:568 /w/u568' >/dev/null
run "$NAME-568" "$WORK/u568" --user 568:568
check "als 568 gestart en healthy" "wait_healthy $NAME-568"
check "als 568: elk proces Uid 568, CapEff 0, NoNewPrivs 1" "procs_ok $NAME-568"
docker rm -f "$NAME-568" >/dev/null

echo "== 5. verkeerde rechten geven een duidelijke Nederlandse fout"
# de map expliciet van root (0755) maken: anders hangt de uitkomst af van de uid van de hostgebruiker
in_work 'chown 0:0 /w/bad && chmod 0755 /w/bad'
docker run -d --name "$NAME-bad" -v "$WORK/bad:/appdata" --user 1000:1000 "$IMAGE" >/dev/null
sleep 8
check "fout 'geen schrijfrechten' in de log" "log_has $NAME-bad 'FOUT: geen schrijfrechten'"

echo
echo "Resultaat: $PASS geslaagd, $FAIL mislukt"
[ "$FAIL" -eq 0 ]
