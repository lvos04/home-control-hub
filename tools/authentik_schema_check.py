"""Controleer het Authentik-API-oppervlak van deze dienst tegen de officiële schema's (alleen ontwikkeling).

    .venv/bin/python tools/authentik_schema_check.py --schemas <map met schema-<versie>.yml> \
        --out docs/b13/authentik-api-verificatie.json

Zonder ``--schemas`` worden de schema's per tag gedownload van GitHub (raw.githubusercontent.com). Per release-lijn
(nieuwste patch uit ``compat.RELEASE_LINES``) wordt gecontroleerd dat elk pad, elke queryparameter en elk veld uit
``compat.USED_API`` bestaat, en dat de verplichte velden van schrijfverzoeken exact overeenkomen. De sha256 van elk
schema moet gelijk zijn aan ``compat.SCHEMA_SHA256``. Exitcode 1 bij een afwijking. Geen runtime-onderdeel.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from integrations.domains.sso.authentik import compat


def _load(version: str, schemas: Path | None) -> bytes:
    if schemas is not None:
        return (schemas / f"schema-{version}.yml").read_bytes()
    url = compat.SCHEMA_SOURCE.format(version=version)
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - vaste https-URL van GitHub
        return bytes(resp.read())


def _params(op: dict[str, Any], components: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for p in op.get("parameters", []):
        if "$ref" in p:
            p = components["parameters"][p["$ref"].rsplit("/", 1)[1]]
        names.add(p["name"])
    return names


def _present(use: compat.ApiUse, paths: dict[str, Any], comps: dict[str, Any]) -> bool:
    ops = paths.get(use.path)
    if ops is None or use.method not in ops:
        return False
    if use.params and not set(use.params) <= _params(ops[use.method], comps):
        return False
    if use.schema and use.fields:
        props = comps["schemas"].get(use.schema, {}).get("properties", {})
        if not set(use.fields) <= set(props):
            return False
    return True


def check_version(version: str, raw: bytes) -> dict[str, Any]:
    doc = yaml.safe_load(raw)
    paths, comps = doc["paths"], doc["components"]
    line = compat.parse_version(version)
    assert line is not None
    problems: list[str] = []
    checked = 0
    for use in compat.USED_API:
        if use.since is not None and line.line < use.since:
            # de grens moet exact zijn: vóór 'since' hoort het kenmerk te ontbreken
            if _present(use, paths, comps):
                problems.append(f"{use.method.upper()} {use.path} {use.params or use.fields}: bestaat al vóór {use.since}")
            continue
        checked += 1
        ops = paths.get(use.path)
        if ops is None or use.method not in ops:
            problems.append(f"{use.method.upper()} {use.path} ontbreekt")
            continue
        missing = set(use.params) - _params(ops[use.method], comps)
        if missing:
            problems.append(f"{use.method.upper()} {use.path}: parameters ontbreken {sorted(missing)}")
        if use.schema:
            schema = comps["schemas"].get(use.schema)
            if schema is None:
                problems.append(f"schema {use.schema} ontbreekt")
                continue
            absent = set(use.fields) - set(schema.get("properties", {}))
            if absent:
                problems.append(f"{use.schema}: velden ontbreken {sorted(absent)}")
            if use.required_request_fields is not None and set(schema.get("required", [])) != set(
                use.required_request_fields
            ):
                problems.append(
                    f"{use.schema}: verplichte velden {sorted(schema.get('required', []))} "
                    f"≠ verwacht {sorted(use.required_request_fields)}"
                )
    redirect = comps["schemas"]["OAuth2ProviderRequest"]["properties"]["redirect_uris"]
    if redirect.get("type") != "array":
        problems.append("OAuth2ProviderRequest.redirect_uris is geen lijst")
    item = comps["schemas"].get("RedirectURIRequest", {})
    if set(item.get("required", [])) != {"matching_mode", "url"}:
        problems.append("RedirectURIRequest heeft niet exact de verplichte velden matching_mode en url")
    return {
        "version": version,
        "schema_sha256": hashlib.sha256(raw).hexdigest(),
        "expected_sha256": compat.SCHEMA_SHA256.get(version),
        "uses_checked": checked,
        "problems": problems,
        "ok": not problems and hashlib.sha256(raw).hexdigest() == compat.SCHEMA_SHA256.get(version),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--schemas", type=Path, help="map met schema-<versie>.yml (anders downloaden)")
    ap.add_argument("--out", type=Path, help="resultaat als JSON")
    args = ap.parse_args(argv)
    results = []
    for y, m, p in compat.RELEASE_LINES:
        version = f"{y}.{m}.{p}"
        results.append(check_version(version, _load(version, args.schemas)))
    report = {
        "checked_on": compat.VERIFIED_ON,
        "source": compat.SCHEMA_SOURCE,
        "tool": "tools/authentik_schema_check.py",
        "used_api": [
            {
                "method": u.method.upper(),
                "path": u.path,
                "purpose_nl": u.purpose_nl,
                "tasks": list(u.tasks),
                "params": list(u.params),
                "schema": u.schema,
                "fields": list(u.fields),
                "since": f"{u.since[0]}.{u.since[1]}" if u.since else None,
                "executed_in_this_version": u.executed,
            }
            for u in compat.USED_API
        ],
        "results": results,
        "all_ok": all(r["ok"] for r in results),
    }
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    for r in results:
        print(f"{r['version']}: {'ok' if r['ok'] else 'AFWIJKING'} ({r['uses_checked']} onderdelen) {r['problems']}")
    return 0 if report["all_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
