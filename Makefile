.PHONY: init-env up up-live down docker-test logs build clean license-check compliance-check sast secrets iac sbom container-scan dast a11y load-test govready

init-env:
	@if [ ! -f .env ] && [ -z "$$POSTGRES_PASSWORD" ]; then \
		python3 -c "import secrets; pw=secrets.token_hex(24); open('.env','w').write(f'POSTGRES_USER=warrant\nPOSTGRES_DB=warrant\nPOSTGRES_PASSWORD={pw}\nDATABASE_URL=postgres://warrant:{pw}@postgres:5432/warrant?sslmode=disable\nTEST_DATABASE_URL=postgres://warrant:{pw}@postgres:5432/postgres?sslmode=disable\n')"; \
		echo "[init-env] Generated unique per-installation random credentials in .env"; \
	fi

up: init-env
	docker compose up --build -d

up-live: init-env
	WARRANT_FEED_MODE=live WARRANT_TRIVY_ENABLED=true docker compose --profile live-feeds up --build -d

down:
	docker compose down -v

docker-test: init-env
	docker compose --profile test run --rm --build verifier

logs:
	docker compose logs -f

build:
	docker compose build

clean:
	docker compose down -v --remove-orphans

license-check:
	python scripts/audit_licenses.py

# ==============================================================================
# 9-Gate Federal DevSecOps & Compliance Pipeline (NIST SP 800-53 Rev 5 / STIG)
# ==============================================================================
compliance-check:
	python scripts/compliance_harness.py --all

sast:
	python scripts/compliance_harness.py --gate sast

secrets:
	python scripts/compliance_harness.py --gate secrets

iac:
	python scripts/compliance_harness.py --gate iac

sbom:
	python scripts/compliance_harness.py --gate sbom

container-scan:
	python scripts/compliance_harness.py --gate sca

dast:
	python scripts/compliance_harness.py --gate dast

a11y:
	python scripts/compliance_harness.py --gate a11y

load-test:
	python scripts/compliance_harness.py --gate load

govready:
	python scripts/compliance_harness.py --gate govready
