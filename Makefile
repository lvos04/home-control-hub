# Ontwikkelcommando's (geen installatiemethode; installeren gaat als standaard TrueNAS Custom App).
PY ?= .venv/bin/python
API := apps/api
IMAGE ?= home-control-hub:dev

.PHONY: lint test e2e interop openapi lock image smoke clean toestanden test-ui schermafdrukken peil-drift ontwerpreview

lint:
	cd $(API) && ../../$(PY) -m ruff check . && ../../$(PY) -m ruff format --check . && ../../$(PY) -m mypy

test:
	cd $(API) && ../../$(PY) -m pytest -q

e2e:
	$(PY) -m pytest -q tests/e2e -p no:cacheprovider

# Statuspagina in Peil (HC11): toestanden uit de echte app (PostgreSQL + Hub-simulator) → Playwright (axe-core,
# overloop 320–1440 px, CSP, focus) → schermafdrukken in docs/screenshots/peil/statuspagina/.
toestanden:
	$(PY) tests/ui/genereer_toestanden.py

test-ui: toestanden
	cd tests/ui && { test -d node_modules || npm ci --no-audit --no-fund; } && npx playwright test

schermafdrukken: toestanden
	cd tests/ui && { test -d node_modules || npm ci --no-audit --no-fund; } && SCHERMAFDRUKKEN=1 npx playwright test

# Onafhankelijke ontwerpreview (contract §13; ADR-0012): de DRAAIENDE dienst (API + worker als processen, eigen
# databases hch_review_<n>) tegen de Hub-simulator; Chromium vult zelf het koppelformulier in en meet per toestand ×
# 320/360/390/768/1440 × licht/donker: axe (WCAG 2.2 AA), contrast in de pagina, doelen, focus, Peil-statusregels.
# Uitvoer en afdrukken: tests/ui/review-uit/ (niet in git; docs/ontwerp/PEIL_REVIEW.md vat samen).
ontwerpreview:
	cd tests/ui && { test -d node_modules || npm ci --no-audit --no-fund; }
	$(PY) tests/ui/ontwerpreview.py

# Versie-gepinde kopie van het Peil-sjabloon (O-14): offline en tegen ai-server-manager op GitHub.
peil-drift:
	python3 tools/peil_kopie.py controleer && python3 tools/peil_kopie.py vergelijk --online

# Interop met de ECHTE Hub (alleen lokaal): HUB_PY = Python van een venv met het pakket 'hub' van ai-server-manager.
interop:
	HCH_REAL_HUB_PYTHON=$(HUB_PY) $(PY) -m pytest -q tests/interop -p no:cacheprovider

openapi:
	$(PY) -m integrations openapi --out docs/openapi/home-control-hub.openapi.json

# Runtime-lock opnieuw maken in een schone omgeving (na wijzigen van afhankelijkheden in pyproject.toml).
lock:
	rm -rf .lockvenv && python3.12 -m venv .lockvenv && .lockvenv/bin/pip install -q ./$(API)
	{ echo "# Runtime-afhankelijkheden (exact gepind) voor de alles-in-één image. Bijwerken: zie Makefile 'lock'."; \
	  .lockvenv/bin/pip freeze --exclude home-control-hub; } > $(API)/requirements.lock
	rm -rf .lockvenv $(API)/build

# Eén build tegelijk en met lage prioriteit (gedeelde bouwomgeving).
image:
	nice -n 10 docker buildx build --load -f deploy/allinone/Dockerfile -t $(IMAGE) .

smoke:
	deploy/allinone/smoke-test.sh $(IMAGE)

clean:
	find . -name __pycache__ -prune -exec rm -rf {} + ; rm -rf $(API)/build .lockvenv
	docker image rm $(IMAGE) 2>/dev/null || true
