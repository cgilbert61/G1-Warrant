.PHONY: up up-live down docker-test logs build clean compliance-check sast secrets iac sbom container-scan dast a11y load-test govready

up:
	docker compose up --build -d

up-live:
	WARRANT_FEED_MODE=live WARRANT_TRIVY_ENABLED=true docker compose --profile live-feeds up --build -d

down:
	docker compose down -v

docker-test:
	docker compose --profile test run --rm --build verifier

logs:
	docker compose logs -f

build:
	docker compose build

clean:
	docker compose down -v --remove-orphans

# ==============================================================================
# 9-Gate Federal DevSecOps & Compliance Pipeline (NIST SP 800-53 / DISA STIG)
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
