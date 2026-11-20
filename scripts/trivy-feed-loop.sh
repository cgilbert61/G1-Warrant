#!/bin/sh
set -eu

API_URL="${WARRANT_API_URL:-http://warrantd:8080}"
ENABLED="${WARRANT_TRIVY_ENABLED:-true}"
TARGETS="${WARRANT_TRIVY_TARGETS:-curlimages/curl:8.3.0=fulfillment-worker,nginx:1.24.0-alpine=checkout-cart-svc}"
MAX_FINDINGS="${WARRANT_TRIVY_MAX_FINDINGS:-2}"
INTERVAL_SEC="${WARRANT_TRIVY_SCAN_INTERVAL_SEC:-3600}"

if [ "$ENABLED" != "true" ] && [ "$ENABLED" != "1" ]; then
  echo "[trivy-sidecar] WARRANT_TRIVY_ENABLED=$ENABLED; sidecar idle."
  exec sleep infinity
fi

echo "[trivy-sidecar] Waiting for warrantd front door ($API_URL/healthz)..."
until curl -fsS "$API_URL/healthz" >/dev/null 2>&1; do
  sleep 2
done
echo "[trivy-sidecar] Connected to warrantd. Starting scheduled real SARIF 2.1.0 image scans..."

while true; do
  OLD_IFS="$IFS"
  IFS=','
  for pair in $TARGETS; do
    IFS="$OLD_IFS"
    IMG="${pair%%=*}"
    SVC="${pair#*=}"
    if [ -z "$IMG" ] || [ -z "$SVC" ]; then
      continue
    fi
    OUT_FILE="/tmp/trivy-${SVC}.sarif"
    echo "[trivy-sidecar] Scanning real container image '$IMG' for target workload '$SVC'..."
    if trivy image --quiet --scanners vuln --severity CRITICAL,HIGH --format sarif -o "$OUT_FILE" "$IMG"; then
      echo "[trivy-sidecar] POSTing genuine SARIF 2.1.0 report for '$SVC' to $API_URL/api/v1/intake/sarif..."
      AUTH_ARGS=""
      if [ -n "${WARRANT_INTAKE_TOKEN:-}" ]; then
        AUTH_ARGS="-H X-Warrant-Intake-Token:${WARRANT_INTAKE_TOKEN}"
      fi
      # shellcheck disable=SC2086
      curl -fsS -X POST \
        -H "Content-Type: application/json" \
        $AUTH_ARGS \
        --data-binary "@${OUT_FILE}" \
        "${API_URL}/api/v1/intake/sarif?target_service=${SVC}&max_findings=${MAX_FINDINGS}" >/dev/null || \
        echo "[trivy-sidecar] Notice: intake returned non-2xx for $SVC"
      rm -f "$OUT_FILE"
    else
      echo "[trivy-sidecar] Warning: trivy scan failed for $IMG"
    fi
  done
  IFS="$OLD_IFS"
  echo "[trivy-sidecar] Scan cycle complete. Sleeping ${INTERVAL_SEC}s..."
  sleep "$INTERVAL_SEC"
done
