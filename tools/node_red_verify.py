"""Controleer de aannames van deze dienst over Node-RED tegen de GEPINDE image in lokale containers (ontwikkeling).

    .venv/bin/python tools/node_red_verify.py --out docs/b11/node-red-verificatie.json

Wat er gebeurt (alleen op de ontwikkelmachine; geen NAS, geen echte apparaten):

1. drie containers van ``catalog.NODE_RED_IMAGE@NODE_RED_DIGEST`` met eigen namen (``hch-nrverify-...``), elk op een
   willekeurige poort op 127.0.0.1, zonder Docker-socket, zonder extra capabilities en als de standaardgebruiker van
   de image:
   - ``kaal``: zonder instellingen (zo ziet een onbeveiligde Node-RED eruit);
   - ``profiel``: met precies de argumenten die deze dienst voor het formulier van de Custom App maakt
     (``policy.define_arguments``);
   - ``andere-sleutel``: hetzelfde profiel met een andere ``credentialSecret``.
2. de eigen code van deze dienst (``NodeRedClient``, ``policy.check_isolation``, ``policy.scan``) praat met die
   containers; elke aanname uit ``nodered.py``/``policy.py``/``restore.py`` wordt één controle in het rapport.
3. de containers (en hun anonieme volumes) worden altijd weer verwijderd.

Dit bewijst het gedrag van de image, niet de installatie op een NAS: het rapport zegt daarom vast
``validatie_echte_nas: "NIET GEVALIDEERD (echte NAS)"``. Exitcode 1 bij een afwijking. Geen runtime-onderdeel.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from integrations.config import Settings
from integrations.domains.automation import policy
from integrations.domains.automation.catalog import (
    FORBIDDEN_NODE_TYPES,
    NODE_RED_DIGEST,
    NODE_RED_IMAGE,
    NODE_RED_PORT,
    NODE_RED_TAG,
    NODE_RED_UID,
)
from integrations.domains.automation.nodered import NodeRedClient, NodeRedError

IMAGE_REF = f"{NODE_RED_IMAGE}@{NODE_RED_DIGEST}"
PREFIX = f"hch-nrverify-{os.getpid()}"
SETTINGS = Settings()
CRED_BLOB_RE = re.compile(r"^[0-9a-f]{32}[A-Za-z0-9+/]+=*$")

CHECKS: list[dict[str, Any]] = []


def check(check_id: str, ok: bool, title_nl: str, **detail: Any) -> bool:
    CHECKS.append({"id": check_id, "ok": bool(ok), "title_nl": title_nl, "detail": detail})
    print(("ok   " if ok else "FOUT ") + check_id + (" " + json.dumps(detail, ensure_ascii=False) if not ok else ""))
    return bool(ok)


def docker(*args: str, check_rc: bool = True) -> str:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True, check=False)  # noqa: S603, S607
    if check_rc and proc.returncode != 0:
        raise RuntimeError(f"docker {args[0]} mislukte: {proc.stderr.strip()[:400]}")
    return proc.stdout.strip()


def start(name: str, arguments: list[str], env: dict[str, str] | None = None) -> str:
    """Start een container en geeft ``http://127.0.0.1:<poort>`` terug zodra de admin-API antwoordt."""
    cmd = [
        "run",
        "-d",
        "--name",
        f"{PREFIX}-{name}",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "-p",
        f"127.0.0.1::{NODE_RED_PORT}",
    ]
    for key, value in (env or {}).items():
        cmd += ["-e", f"{key}={value}"]
    docker(*cmd, IMAGE_REF, *arguments)
    port = docker("port", f"{PREFIX}-{name}", f"{NODE_RED_PORT}/tcp").splitlines()[0].rsplit(":", 1)[1]
    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            if httpx.get(base + "/auth/login", timeout=2.0, trust_env=False).status_code == 200:
                return base
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    raise RuntimeError(
        f"container {name} kwam niet op: {docker('logs', '--tail', '30', f'{PREFIX}-{name}', check_rc=False)}"
    )


def cleanup() -> None:
    names = docker("ps", "-a", "--filter", f"name={PREFIX}-", "--format", "{{.Names}}", check_rc=False).split()
    for name in names:
        docker("rm", "-f", "-v", name, check_rc=False)


def raw(base: str, method: str, path: str, token: str | None = None, **kw: Any) -> httpx.Response:
    headers = dict(kw.pop("headers", {}))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.request(method, base + path, headers=headers, timeout=15.0, trust_env=False, **kw)


def token_for(base: str, username: str, password: str, scope: str = "") -> httpx.Response:
    form = {"client_id": "node-red-admin", "grant_type": "password", "scope": scope, "username": username}
    return raw(base, "POST", "/auth/token", data={**form, "password": password})


def cred_file(name: str) -> Any:
    text = docker("exec", f"{PREFIX}-{name}", "cat", "/data/flows_cred.json", check_rc=False)
    try:
        return json.loads(text)
    except ValueError:
        return None


def demo_flows() -> list[dict[str, Any]]:
    """Een flow met een http request-node die een gebruikersnaam en wachtwoord als credentials heeft."""
    return [
        {"id": "a1b2c3d4e5f60001", "type": "tab", "label": "Verificatie", "disabled": False, "info": ""},
        {
            "id": "a1b2c3d4e5f60002",
            "type": "inject",
            "z": "a1b2c3d4e5f60001",
            "name": "",
            "props": [],
            "repeat": "",
            "once": False,
            "x": 120,
            "y": 80,
            "wires": [["a1b2c3d4e5f60003"]],
        },
        {
            "id": "a1b2c3d4e5f60003",
            "type": "http request",
            "z": "a1b2c3d4e5f60001",
            "name": "",
            "method": "GET",
            "ret": "txt",
            "url": "http://127.0.0.1:9/nergens",
            "authType": "basic",
            "x": 320,
            "y": 80,
            "wires": [[]],
        },
    ]


def verify_plain() -> None:
    # NODE_RED_CREDENTIAL_SECRET staat hier bewust in de omgeving: de image negeert die variabele (zie kaal_env)
    base = start("kaal", [], env={"NODE_RED_CREDENTIAL_SECRET": "wordt-genegeerd-" + secrets.token_hex(8)})
    login = raw(base, "GET", "/auth/login")
    check(
        "kaal_geen_aanmelding",
        login.json() == {},
        "Zonder adminAuth geeft GET /auth/login een leeg object",
        body=login.json(),
    )
    anon = {p: raw(base, "GET", p).status_code for p in policy.ANONYMOUS_PATHS}
    check(
        "kaal_anoniem_leesbaar",
        all(s == 200 for s in anon.values()),
        "Zonder adminAuth is alles anoniem leesbaar",
        http=anon,
    )
    nodes = raw(base, "GET", "/nodes", headers={"Accept": "application/json"}).json()
    types = policy.type_modules(nodes)
    check(
        "kaal_exec_geladen",
        all(t in types for t in FORBIDDEN_NODE_TYPES),
        "Zonder nodesExcludes is de exec-node geladen",
        verboden_geladen=sorted(t for t in FORBIDDEN_NODE_TYPES if t in types),
    )
    check(
        "kaal_alleen_kernmodule",
        set(types.values()) == {"node-red"},
        "De image bevat alleen nodes uit de kernmodule 'node-red'",
        modules=sorted(set(types.values())),
    )
    settings = raw(base, "GET", "/settings").json()
    check(
        "kaal_instellingen",
        settings.get("functionExternalModules") is True
        and settings.get("flowEncryptionType") == "system"
        and settings.get("externalModules") == {},
        "Standaard: function-modules aan, palette open, credentials met een systeemsleutel",
        functionExternalModules=settings.get("functionExternalModules"),
        flowEncryptionType=settings.get("flowEncryptionType"),
        externalModules=settings.get("externalModules"),
    )
    check(
        "kaal_env_credential_secret_genegeerd",
        settings.get("flowEncryptionType") == "system",
        "De omgevingsvariabele NODE_RED_CREDENTIAL_SECRET wordt door de image niet gebruikt (alleen --define werkt)",
        flowEncryptionType=settings.get("flowEncryptionType"),
    )
    diag = raw(base, "GET", "/diagnostics").json()
    admin_auth = diag.get("runtime", {}).get("settings", {}).get("adminAuth")
    check("kaal_diagnostics_unset", admin_auth == "UNSET", "Diagnostics meldt adminAuth: UNSET", adminAuth=admin_auth)
    check(
        "versie_is_gepinde_tag",
        settings.get("version") == NODE_RED_TAG,
        "De image meldt de gepinde versie",
        version=settings.get("version"),
        tag=NODE_RED_TAG,
    )
    # de eigen client weigert een onbeveiligde Node-RED en de isolatiecontrole meldt een afwijking
    client = NodeRedClient(base, policy.SERVICE_USER, "maakt-niet-uit", SETTINGS)
    try:
        client.get_flows()
        refused = None
    except NodeRedError as exc:
        refused = exc.reason
    check(
        "kaal_client_weigert",
        refused == "niet_beveiligd",
        "De client van deze dienst leest niets uit een onbeveiligde Node-RED",
        reden=refused,
    )
    report = policy.check_isolation(NodeRedClient(base, policy.SERVICE_USER, "maakt-niet-uit", SETTINGS), ("node-red",))
    check(
        "kaal_isolatie_afwijking",
        report["status"] == "afwijking" and {"editor_aanmelding", "anoniem_geweigerd"} <= set(report["afwijkingen"]),
        "De isolatiecontrole meldt een onbeveiligde Node-RED als afwijking",
        status=report["status"],
        afwijkingen=report["afwijkingen"],
    )


def verify_profile() -> None:
    service_password = secrets.token_urlsafe(32)
    admin_password = secrets.token_urlsafe(18)
    secret_a = secrets.token_urlsafe(48)
    secret_b = secrets.token_urlsafe(48)
    service_hash, admin_hash = policy.hash_password(service_password), policy.hash_password(admin_password)
    base = start("profiel", policy.define_arguments(service_hash, admin_hash, secret_a))
    other = start("andere-sleutel", policy.define_arguments(service_hash, admin_hash, secret_b))

    uid = docker("exec", f"{PREFIX}-profiel", "id", "-u")
    check(
        "gebruiker_niet_root",
        uid == str(NODE_RED_UID),
        "De image draait standaard als een gewone gebruiker",
        uid=uid,
        verwacht=NODE_RED_UID,
    )
    login = raw(base, "GET", "/auth/login").json()
    check(
        "profiel_vraagt_aanmelding",
        login.get("type") == "credentials",
        "Met het profiel vraagt de editor een aanmelding",
        type=login.get("type"),
    )
    anon = {p: raw(base, "GET", p).status_code for p in policy.ANONYMOUS_PATHS}
    check(
        "profiel_anoniem_401",
        all(s == 401 for s in anon.values()),
        "Zonder aanmelding: 401 op flows, nodes en instellingen",
        http=anon,
    )
    anon_post = raw(base, "POST", "/flows", json=[], headers={"Node-RED-Deployment-Type": "full"}).status_code
    check(
        "profiel_anoniem_schrijven_401", anon_post == 401, "Zonder aanmelding kan niemand flows zetten", http=anon_post
    )

    wrong = token_for(base, policy.SERVICE_USER, "fout-wachtwoord")
    check("fout_wachtwoord_403", wrong.status_code == 403, "Een fout wachtwoord geeft 403", http=wrong.status_code)
    star = token_for(base, policy.SERVICE_USER, service_password, scope="*")
    check(
        "dienstaccount_scope_ster_geweigerd",
        star.status_code == 403,
        "Het dienstaccount krijgt geen token met scope '*'",
        http=star.status_code,
    )
    admin = token_for(base, policy.ADMIN_USER, admin_password, scope="*")
    check(
        "beheeraccount_kan_aanmelden",
        admin.status_code == 200,
        "Het beheeraccount meldt aan met het bcrypt-wachtwoord uit het profiel",
        http=admin.status_code,
    )
    admin_token = admin.json()["access_token"]

    # de isolatiecontrole van deze dienst, met het dienstaccount
    report = policy.check_isolation(NodeRedClient(base, policy.SERVICE_USER, service_password, SETTINGS), ("node-red",))
    measured = {r["id"]: r["status"] for r in report["checks"] if r["id"] in policy.MEASURED}
    check(
        "profiel_isolatie_in_orde",
        report["status"] == "gemeten_in_orde" and all(s == "ok" for s in measured.values()),
        "De isolatiecontrole van deze dienst meet het profiel als in orde",
        status=report["status"],
        controles=measured,
        niet_meetbaar=report["niet_meetbaar"],
    )

    with NodeRedClient(base, policy.SERVICE_USER, service_password, SETTINGS) as client:
        settings = client.get_settings()
        check(
            "dienstaccount_rechten",
            settings.get("user", {}).get("permissions") == list(policy.SERVICE_PERMISSIONS),
            "Het dienstaccount heeft precies zijn minimale rechten",
            rechten=settings.get("user", {}).get("permissions"),
        )
        types = policy.type_modules(client.get_nodes())
        check(
            "profiel_exec_niet_geladen",
            not any(t in types for t in FORBIDDEN_NODE_TYPES),
            "Met nodesExcludes is de exec-node niet geladen",
            verboden_geladen=sorted(t for t in FORBIDDEN_NODE_TYPES if t in types),
        )
        service_token = client._token
        install = raw(base, "POST", "/nodes", token=service_token, json={"module": "node-red-node-random"}).status_code
        check(
            "dienstaccount_kan_niets_installeren",
            install in (401, 403, 404),
            "Het dienstaccount kan geen module installeren",
            http=install,
        )
        install_admin = raw(
            base, "POST", "/nodes", token=admin_token, json={"module": "node-red-node-random"}
        ).status_code
        check(
            "palette_installatie_uit",
            install_admin == 404,
            "Ook de beheerder kan via de editor geen module installeren (404)",
            http=install_admin,
        )

        # --- flows met credentials: de beheerder zet ze in de editor
        first = client.get_flows()
        check(
            "flows_v2_vorm",
            len(first.rev) == 64,
            "GET /flows (v2) geeft de flows en een rev (sha256-hex)",
            rev_lengte=len(first.rev),
            nodes=len(first.flows),
        )
        flows = demo_flows()
        with_creds = json.loads(json.dumps(flows))
        with_creds[2]["credentials"] = {"user": "verificatie-gebruiker", "password": secrets.token_urlsafe(16)}
        deploy = raw(
            base,
            "POST",
            "/flows",
            token=admin_token,
            json={"rev": first.rev, "flows": with_creds},
            headers={"Node-RED-API-Version": "v2", "Node-RED-Deployment-Type": "full"},
        )
        check(
            "beheerder_zet_flows",
            deploy.status_code == 200 and "rev" in deploy.json(),
            "De beheerder zet flows met credentials (v2 + rev)",
            http=deploy.status_code,
        )
        doc = client.get_flows()
        leaked = [n["id"] for n in doc.flows if "credentials" in n]
        check(
            "flows_zonder_credentials",
            not leaked and len(doc.flows) == 3,
            "GET /flows geeft nooit credentials terug",
            nodes=len(doc.flows),
            met_credentials=leaked,
        )
        blob = cred_file("profiel")
        blob_ok = isinstance(blob, dict) and set(blob) == {"$"} and bool(CRED_BLOB_RE.match(str(blob.get("$"))))
        check(
            "credentials_bestand_versleuteld",
            blob_ok,
            'flows_cred.json is één versleuteld blok {"$": "<32 hex><base64>"}',
            sleutels=sorted(blob) if isinstance(blob, dict) else None,
        )
        cred_view = raw(base, "GET", "/credentials/http-request/a1b2c3d4e5f60003", token=admin_token)
        seen = cred_view.json() if cred_view.status_code == 200 else {}
        check(
            "credentials_aanwezig_voor_herstel",
            seen.get("user") == "verificatie-gebruiker" and seen.get("has_password") is True,
            "Node-RED kent de credentials van de node (wachtwoord alleen als has_password)",
            http=cred_view.status_code,
            velden=sorted(seen),
        )
        service_cred = raw(base, "GET", "/credentials/http-request/a1b2c3d4e5f60003", token=service_token).status_code
        check(
            "dienstaccount_leest_geen_credentials",
            service_cred == 401,
            "Het dienstaccount kan geen credentials opvragen",
            http=service_cred,
        )
        checksum_before = policy.flows_checksum(doc.flows)

        # --- verouderde rev wordt geweigerd; er wordt niets overschreven
        try:
            client.post_flows(first.rev, [])
            stale = None
        except NodeRedError as exc:
            stale = exc.reason
        check(
            "verouderde_rev_geweigerd",
            stale == "versie_conflict",
            "POST /flows met een verouderde rev geeft 409 (niets overschreven)",
            reden=stale,
        )
        check("na_weigering_ongewijzigd", client.get_flows().rev == doc.rev, "Na de weigering is de rev ongewijzigd")

        # --- alles weghalen (credentials verdwijnen), daarna herstellen met het bewaarde blok
        emptied_rev = client.post_flows(doc.rev, [])
        gone = raw(base, "GET", "/credentials/http-request/a1b2c3d4e5f60003", token=admin_token)
        check(
            "na_leegmaken_geen_credentials",
            gone.status_code == 200 and "user" not in gone.json(),
            "Na het weghalen van de flows zijn de credentials weg",
            velden=sorted(gone.json()),
        )
        restored_rev = client.post_flows(emptied_rev, doc.flows, credentials=blob)
        back = client.get_flows()
        check(
            "herstel_flows_gelijk",
            back.rev == restored_rev and policy.flows_checksum(back.flows) == checksum_before,
            "Na het herstel zijn de flows byte-gelijk (checksum) aan de momentopname",
            checksum_gelijk=policy.flows_checksum(back.flows) == checksum_before,
        )
        again = raw(base, "GET", "/credentials/http-request/a1b2c3d4e5f60003", token=admin_token)
        seen = again.json() if again.status_code == 200 else {}
        check(
            "herstel_credentials_terug",
            seen.get("user") == "verificatie-gebruiker" and seen.get("has_password") is True,
            "Het versleutelde blok zet de credentials terug zonder dat deze dienst ze kan lezen",
            http=again.status_code,
            velden=sorted(seen),
        )

        # --- een flow met een exec-node wordt door Node-RED zelf NIET geweigerd: de scan van deze dienst moet blokkeren
        exec_flows = [
            *back.flows,
            {
                "id": "a1b2c3d4e5f60009",
                "type": "exec",
                "z": "a1b2c3d4e5f60001",
                "name": "",
                "command": "id",
                "addpay": "",
                "append": "",
                "useSpawn": "false",
                "timer": "",
                "winHide": False,
                "oldrc": False,
                "x": 320,
                "y": 160,
                "wires": [[], [], []],
            },
        ]
        accepted = raw(
            base,
            "POST",
            "/flows",
            token=admin_token,
            json={"rev": back.rev, "flows": exec_flows},
            headers={"Node-RED-API-Version": "v2", "Node-RED-Deployment-Type": "full"},
        )
        scan = policy.scan(client.get_flows().flows, policy.type_modules(client.get_nodes()), ("node-red",))
        blocked = [t.blocked_reason for t in scan.tabs if t.blocked]
        check(
            "exec_flow_aangenomen_maar_gescand",
            accepted.status_code == 200 and len(blocked) == 1,
            "Node-RED neemt een flow met een (niet geladen) exec-node aan; de scan van deze dienst blokkeert de flow",
            http=accepted.status_code,
            geblokkeerd=blocked,
        )
        state = raw(base, "GET", "/flows/state", token=admin_token)
        check(
            "exec_type_niet_geregistreerd",
            "exec" not in policy.type_modules(client.get_nodes()),
            "Het type exec blijft ongeregistreerd (de node kan niet draaien)",
            flows_state_http=state.status_code,
        )

    # --- andere credentialSecret: Node-RED weigert het blok en verandert niets
    with NodeRedClient(other, policy.SERVICE_USER, service_password, SETTINGS) as client2:
        before = client2.get_flows()
        try:
            client2.post_flows(before.rev, demo_flows(), credentials=blob)
            refused = None
        except NodeRedError as exc:
            refused = exc.reason
        check(
            "andere_sleutel_geweigerd",
            refused == "credentials_niet_te_ontsleutelen",
            "Met een andere credentialSecret weigert Node-RED het blok (400 credentials_load_failed)",
            reden=refused,
        )
        check(
            "andere_sleutel_ongewijzigd",
            client2.get_flows().rev == before.rev,
            "Na die weigering zijn de flows ongewijzigd",
        )

    # --- token intrekken werkt
    probe = NodeRedClient(base, policy.SERVICE_USER, service_password, SETTINGS)
    probe.login()
    old = probe._token
    probe.close()
    after = raw(base, "GET", "/settings", token=old).status_code
    check("token_ingetrokken", after == 401, "Na POST /auth/revoke is het token ongeldig", http=after)


def tag_digest() -> None:
    """De tag in het register wijst naar de gepinde digest (alleen lezen; netwerk nodig)."""
    command = ["docker", "buildx", "imagetools", "inspect", f"{NODE_RED_IMAGE}:{NODE_RED_TAG}"]
    proc = subprocess.run(  # noqa: S603
        [*command, "--format", "{{json .Manifest}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    digest = None
    if proc.returncode == 0:
        try:
            digest = json.loads(proc.stdout).get("digest")
        except ValueError:
            digest = None
    check(
        "tag_wijst_naar_digest",
        digest == NODE_RED_DIGEST,
        "De tag in het register wijst naar de gepinde digest",
        register=digest,
        gepind=NODE_RED_DIGEST,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    image_id = None
    try:
        docker("pull", "-q", IMAGE_REF)
        image_id = docker("image", "inspect", IMAGE_REF, "--format", "{{.Id}}")
        tag_digest()
        verify_plain()
        verify_profile()
    finally:
        cleanup()
    report = {
        "checked_on": dt.datetime.now(dt.UTC).date().isoformat(),
        "tool": "tools/node_red_verify.py",
        "image": {"repository": NODE_RED_IMAGE, "tag": NODE_RED_TAG, "digest": NODE_RED_DIGEST, "image_id": image_id},
        "omgeving": "lokale Docker-containers op de ontwikkelmachine (geen NAS, geen echte apparaten)",
        "validatie_echte_nas": "NIET GEVALIDEERD (echte NAS)",
        "niet_gemeten": [
            "installatie via het formulier van de TrueNAS Custom App",
            "netwerkafscherming op de NAS (alleen LAN)",
            "dataset-rechten en de alleen-lezen koppeling van de datamap",
        ],
        "checks": CHECKS,
        "all_ok": all(c["ok"] for c in CHECKS) and bool(CHECKS),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{sum(1 for c in CHECKS if c['ok'])}/{len(CHECKS)} controles in orde → {args.out}")
    return 0 if report["all_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
