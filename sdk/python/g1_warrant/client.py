"""Typed Synchronous Python Client for the G1-Warrant Control Plane (warrantd)."""

from __future__ import annotations

import base64
import http.client
import json
import os
import urllib.parse
from pathlib import Path
from typing import Any

from .crypto import (
    PublicIdentityBundle,
    SignerKeyBundle,
    draft_governance_envelope,
    draft_principal_enroll_envelope,
    draft_principal_revoke_envelope,
    draft_principal_rotate_and_revoke_envelope,
    sha256_hex,
)


class WarrantAPIError(RuntimeError):
    """Raised when warrantd returns a non-2xx HTTP response."""

    def __init__(self, status_code: int, method: str, endpoint: str, message: str):
        super().__init__(f"WarrantAPIError ({method} {endpoint} -> HTTP {status_code}): {message}")
        self.status_code = status_code
        self.method = method
        self.endpoint = endpoint
        self.message = message


class AuditorScopeViolationError(WarrantAPIError):
    """Raised when an external 3PAO auditor bearer token (g1aud_*) calls a non-auditor endpoint."""


class WarrantClient:
    """Remote Python client for G1-Warrant (`warrantd`)."""

    def __init__(
        self,
        base_url: str | None = None,
        auditor_token: str | None = None,
        timeout: float = 30.0,
        operator_token: str | None = None,
        automation_token: str | None = None,
        intake_token: str | None = None,
        estate_read_token: str | None = None,
        signer_bundle: SignerKeyBundle | None = None,
    ) -> None:
        raw_url = (base_url or os.environ.get("WARRANT_API_URL") or "http://localhost:8080").rstrip("/")
        parsed = urllib.parse.urlparse(raw_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"Invalid G1-Warrant base_url {raw_url!r}; must be http:// or https://")
        self.base_url = raw_url
        self._scheme = parsed.scheme
        self._host = parsed.hostname
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._base_path = parsed.path.rstrip("/")
        self.auditor_token = (auditor_token or os.environ.get("WARRANT_AUDITOR_TOKEN") or "").strip()
        self.operator_token = (operator_token or os.environ.get("WARRANT_OPERATOR_TOKEN") or "").strip()
        self.automation_token = (automation_token or os.environ.get("WARRANT_AUTOMATION_TOKEN") or "").strip()
        self.intake_token = (intake_token or os.environ.get("WARRANT_INTAKE_TOKEN") or "").strip()
        self.estate_read_token = (estate_read_token or os.environ.get("WARRANT_ESTATE_READ_TOKEN") or "").strip()
        self.signer_bundle = signer_bundle
        self.timeout = timeout

    def _request_raw(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str | None = None,
        bearer_override: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> bytes:
        full_path = f"{self._base_path}{path}"
        conn_cls = http.client.HTTPSConnection if self._scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(self._host, self._port, timeout=self.timeout)
        headers: dict[str, str] = {"User-Agent": "g1-warrant-python-sdk/1.4.0"}
        if content_type:
            headers["Content-Type"] = content_type
        tok = (bearer_override if bearer_override is not None else self.auditor_token).strip()
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        if self.operator_token and bearer_override is None and not self.auditor_token:
            headers["X-Warrant-Operator-Token"] = self.operator_token
        if self.automation_token and bearer_override is None and not self.auditor_token:
            headers["X-Warrant-Automation-Token"] = self.automation_token
        if self.intake_token:
            headers["X-Warrant-Intake-Token"] = self.intake_token
        if self.estate_read_token:
            headers["X-Warrant-Estate-Read-Token"] = self.estate_read_token
        if extra_headers:
            headers.update(extra_headers)

        try:
            conn.request(method, full_path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_bytes = resp.read()
        finally:
            conn.close()

        if resp.status >= 300:
            msg = resp_bytes.decode("utf-8", errors="replace").strip()
            try:
                err_json = json.loads(msg)
                msg = err_json.get("error") or err_json.get("reason") or msg
            except Exception:
                pass
            if resp.status == 403 and "AUDITOR_TOKEN_SCOPE_VIOLATION" in msg:
                raise AuditorScopeViolationError(resp.status, method, path, msg)
            raise WarrantAPIError(resp.status, method, path, msg)

        return resp_bytes

    def _request_json(
        self,
        method: str,
        path: str,
        payload: Any = None,
        bearer_override: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        body: bytes | None = None
        ctype: str | None = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            ctype = "application/json"
        raw = self._request_raw(
            method, path, body=body, content_type=ctype, bearer_override=bearer_override, extra_headers=extra_headers
        )
        return json.loads(raw.decode("utf-8")) if raw else None

    def _request_action_json(
        self,
        method: str,
        path: str,
        gov_action: str,
        gov_fields: dict[str, Any] | None = None,
        payload: Any = None,
        signer_bundle: SignerKeyBundle | None = None,
    ) -> Any:
        body: bytes | None = None
        ctype: str | None = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            ctype = "application/json"

        extra: dict[str, str] | None = None
        active_signer = signer_bundle or self.signer_bundle
        if active_signer is not None:
            canonical_path = urllib.parse.urlsplit(path).path or path
            scoped_fields = dict(gov_fields or {})
            scoped_fields["http_method"] = method.upper()
            scoped_fields["canonical_path"] = canonical_path
            scoped_fields["request_body_sha256"] = sha256_hex(body or b"")
            env = draft_governance_envelope(gov_action, scoped_fields, ttl_seconds=300)
            active_signer.sign_envelope(1, env)
            extra = {"X-Warrant-Governance-DSSE": base64.b64encode(json.dumps(env).encode("utf-8")).decode("ascii")}

        raw = self._request_raw(method, path, body=body, content_type=ctype, extra_headers=extra)
        return json.loads(raw.decode("utf-8")) if raw else None

    # ------------------------------------------------------------------
    # Core Health, Scoreboard & Bootstrap
    # ------------------------------------------------------------------
    def health(self) -> dict[str, Any]:
        return self._request_json("GET", "/healthz")

    def scoreboard(self) -> dict[str, Any]:
        return self._request_json("GET", "/api/v1/scoreboard")

    def bootstrap(self) -> dict[str, Any]:
        return self._request_json("GET", "/api/v1/bootstrap")

    def kernel_public_key_b64(self) -> str:
        snap = self.bootstrap()
        return str(snap["kernel_public_key"]["public_key_b64"])

    def kernel_public_key_ring(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/kernel-keys")

    # ------------------------------------------------------------------
    # N1 Principals, Genesis Seal, Standing Warrants & Emergency Freeze
    # ------------------------------------------------------------------
    def list_principals(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/principals")

    def register_principal(
        self,
        public_or_signer_bundle: PublicIdentityBundle | SignerKeyBundle | dict[str, Any],
        admin_token: str | None = None,
        slot1_signer: SignerKeyBundle | None = None,
        slot2_signer: SignerKeyBundle | None = None,
    ) -> dict[str, Any]:
        """Enroll an Ed25519 AC-5 public key via POST /api/v1/principals/register.

        - Prior to bootstrap seal: pass `admin_token` (or `$WARRANT_BOOTSTRAP_ADMIN_TOKEN`).
        - After bootstrap seal: pass `slot1_signer` (`SERVICE_OWNER`) and `slot2_signer` (`AUTHORIZING_OFFICIAL`)
          to co-sign a 2-of-2 DSSE Principal Governance envelope (`ENROLL_PRINCIPAL`).
        - Private keys are NEVER transmitted over the network; passing a raw dict containing `private_key*` raises `ValueError`.
        """
        if isinstance(public_or_signer_bundle, SignerKeyBundle):
            pub = public_or_signer_bundle.to_public_identity()
        elif isinstance(public_or_signer_bundle, PublicIdentityBundle):
            pub = public_or_signer_bundle
        else:
            pub = PublicIdentityBundle.from_dict(dict(public_or_signer_bundle))

        if slot1_signer is not None or slot2_signer is not None:
            if slot1_signer is None or slot2_signer is None:
                raise ValueError("Both slot1_signer (SERVICE_OWNER) and slot2_signer (AUTHORIZING_OFFICIAL) are required")
            env = draft_principal_enroll_envelope(pub)
            slot1_signer.sign_envelope(1, env)
            slot2_signer.sign_envelope(2, env)
            return self._request_json("POST", "/api/v1/principals/register", env)

        tok = (admin_token or os.environ.get("WARRANT_BOOTSTRAP_ADMIN_TOKEN") or "").strip()
        if not tok:
            raise ValueError("admin_token (genesis unsealed) OR slot1_signer + slot2_signer (2-of-2 DSSE) is required")
        pub_payload = {
            "principal_id": pub.principal_id,
            "email": pub.email,
            "display_name": pub.display_name,
            "role": pub.role,
            "key_id": pub.key_id,
            "alg": pub.alg or "Ed25519",
            "public_key_b64": pub.public_key_b64,
        }
        return self._request_json(
            "POST", "/api/v1/principals/register", pub_payload, extra_headers={"X-Warrant-Admin-Token": tok}
        )

    def seal_bootstrap(
        self,
        admin_token: str | None = None,
        signer_bundle: SignerKeyBundle | None = None,
    ) -> dict[str, Any]:
        """Permanently seal genesis bootstrap via POST /api/v1/bootstrap/seal (requires >=1 active SO and >=1 active AO)."""
        active_signer = signer_bundle or self.signer_bundle
        if active_signer is not None:
            env = draft_governance_envelope("SEAL_BOOTSTRAP", {})
            active_signer.sign_envelope(1, env)
            return self._request_json("POST", "/api/v1/bootstrap/seal", env)
        tok = (admin_token or os.environ.get("WARRANT_BOOTSTRAP_ADMIN_TOKEN") or "").strip()
        if not tok:
            raise ValueError("admin_token or signer_bundle is required to seal genesis bootstrap")
        return self._request_json("POST", "/api/v1/bootstrap/seal", {}, extra_headers={"X-Warrant-Admin-Token": tok})

    def revoke_principal(
        self,
        principal_id: str = "",
        key_fingerprint: str = "",
        reason_code: str = "SDK_KEY_REVOCATION",
        revoked_by: str = "g1-warrant-python-sdk",
        signer_bundle: SignerKeyBundle | None = None,
        dsse_envelope: dict[str, Any] | None = None,
        slot1_signer: SignerKeyBundle | None = None,
        slot2_signer: SignerKeyBundle | None = None,
    ) -> dict[str, Any]:
        """Revoke a principal via 1-of-2 self-revocation (`signer_bundle`) or 2-of-2 peer revocation (`slot1_signer` + `slot2_signer`)."""
        if dsse_envelope is not None:
            return self._request_json("POST", "/api/v1/principals/revoke", dsse_envelope)
        if slot1_signer is not None or slot2_signer is not None:
            if slot1_signer is None or slot2_signer is None:
                raise ValueError("Both slot1_signer (SERVICE_OWNER) and slot2_signer (AUTHORIZING_OFFICIAL) are required for 2-of-2 peer revocation")
            env = draft_principal_revoke_envelope(
                target_principal_id=principal_id,
                target_key_fingerprint=key_fingerprint,
                reason_code=reason_code,
            )
            slot1_signer.sign_envelope(1, env)
            slot2_signer.sign_envelope(2, env)
            return self._request_json("POST", "/api/v1/principals/revoke", env)
        active_signer = signer_bundle or self.signer_bundle
        if active_signer is not None:
            env = draft_principal_revoke_envelope(
                target_principal_id=principal_id,
                target_key_fingerprint=key_fingerprint,
                reason_code=reason_code,
            )
            active_signer.sign_envelope(1, env)
            return self._request_json("POST", "/api/v1/principals/revoke", env)
        return self._request_json(
            "POST",
            "/api/v1/principals/revoke",
            {
                "principal_id": principal_id,
                "key_fingerprint": key_fingerprint,
                "reason_code": reason_code,
                "revoked_by": revoked_by,
            },
        )

    def rotate_and_revoke_principal(
        self,
        replacement_public_or_signer_bundle: PublicIdentityBundle | SignerKeyBundle | dict[str, Any],
        target_principal_id: str = "",
        target_key_fingerprint: str = "",
        reason_code: str = "ATOMIC_DUAL_KEY_ROTATION_AND_REVOCATION",
        slot1_signer: SignerKeyBundle | None = None,
        slot2_signer: SignerKeyBundle | None = None,
        dsse_envelope: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Atomically enroll a replacement principal and revoke a target principal via 2-of-2 ROTATE_AND_REVOKE_PRINCIPAL."""
        if dsse_envelope is not None:
            return self._request_json("POST", "/api/v1/principals/rotate-and-revoke", dsse_envelope)
        if slot1_signer is None or slot2_signer is None:
            raise ValueError("Both slot1_signer (SERVICE_OWNER) and slot2_signer (AUTHORIZING_OFFICIAL) are required")
        env = draft_principal_rotate_and_revoke_envelope(
            replacement_public_identity=replacement_public_or_signer_bundle,
            target_principal_id=target_principal_id,
            target_key_fingerprint=target_key_fingerprint,
            reason_code=reason_code,
        )
        slot1_signer.sign_envelope(1, env)
        slot2_signer.sign_envelope(2, env)
        return self._request_json("POST", "/api/v1/principals/rotate-and-revoke", env)

    def list_warrants(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/warrants")

    def create_warrant(self, dsse_envelope: dict[str, Any]) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/warrants", dsse_envelope)

    def verify_warrant(self, warrant_id: str) -> dict[str, Any]:
        safe_id = urllib.parse.quote(warrant_id, safe="")
        try:
            return self._request_json("POST", f"/api/v1/warrants/{safe_id}/verify", {})
        except WarrantAPIError as exc:
            if exc.status_code == 422:
                return {"valid": False, "reason": exc.message}
            raise

    def trigger_freeze(
        self,
        mode: str = "FREEZE_HOLD",
        actor: str = "python-sdk-operator",
        reason_code: str = "EMERGENCY_FREEZE",
        signer_bundle: SignerKeyBundle | None = None,
    ) -> dict[str, Any]:
        return self._request_action_json(
            "POST",
            "/api/v1/freeze",
            "EMERGENCY_FREEZE",
            {"freeze_mode": mode, "reason_code": reason_code},
            payload={"mode": mode, "actor": actor, "reason_code": reason_code},
            signer_bundle=signer_bundle,
        )

    def thaw_freeze(self, dsse_envelope: dict[str, Any]) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/freeze/thaw", dsse_envelope)

    # ------------------------------------------------------------------
    # Pipeline, Traces, SARIF Intake & Simulations
    # ------------------------------------------------------------------
    def list_pipeline(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/pipeline")

    def list_traces(self, remediation_id: str) -> list[dict[str, Any]]:
        safe_id = urllib.parse.quote(remediation_id, safe="")
        return self._request_json("GET", f"/api/v1/pipeline/{safe_id}/traces")

    def emergency_rollback(
        self,
        remediation_id: str,
        actor: str = "python-sdk-incident-commander",
        reason: str = "POST_PROMOTION_REGRESSION",
        signer_bundle: SignerKeyBundle | None = None,
    ) -> dict[str, Any]:
        """Execute atomic 3-step Contain-Before-Unban Quarantined Rollback."""
        safe_id = urllib.parse.quote(remediation_id, safe="")
        return self._request_action_json(
            "POST",
            f"/api/v1/pipeline/{safe_id}/emergency-rollback",
            "EMERGENCY_ROLLBACK",
            {"remediation_id": remediation_id, "reason_code": reason},
            payload={"actor": actor, "reason": reason},
            signer_bundle=signer_bundle,
        )

    def ingest_sarif(
        self,
        sarif_payload: bytes | str | Path | dict[str, Any],
        target_service: str | None = None,
        profile: str | None = None,
        max_findings: int | None = None,
    ) -> list[dict[str, Any]]:
        if isinstance(sarif_payload, Path):
            raw = sarif_payload.read_bytes()
        elif isinstance(sarif_payload, dict):
            raw = json.dumps(sarif_payload).encode("utf-8")
        elif isinstance(sarif_payload, str):
            raw = sarif_payload.encode("utf-8")
        else:
            raw = sarif_payload

        params: dict[str, str] = {}
        if target_service:
            params["target_service"] = target_service
        if profile:
            params["profile"] = profile
        if max_findings and max_findings > 0:
            params["max_findings"] = str(max_findings)

        path = "/api/v1/intake/sarif"
        if params:
            path += "?" + urllib.parse.urlencode(params)
        resp = self._request_raw("POST", path, body=raw, content_type="application/json")
        return json.loads(resp.decode("utf-8"))

    def ingest_secret_scan(
        self,
        secret_scan_payload: bytes | str | Path | list[dict[str, Any]] | dict[str, Any],
        target_service: str | None = None,
    ) -> list[dict[str, Any]]:
        """Submit Gitleaks (JSON/SARIF) or GitGuardian secret-exposure findings for zero-prose rotation."""
        if isinstance(secret_scan_payload, Path):
            raw = secret_scan_payload.read_bytes()
        elif isinstance(secret_scan_payload, (dict, list)):
            raw = json.dumps(secret_scan_payload).encode("utf-8")
        elif isinstance(secret_scan_payload, str):
            raw = secret_scan_payload.encode("utf-8")
        else:
            raw = secret_scan_payload

        path = "/api/v1/intake/secrets"
        if target_service:
            path += "?" + urllib.parse.urlencode({"target_service": target_service})
        resp = self._request_raw("POST", path, body=raw, content_type="application/json")
        return json.loads(resp.decode("utf-8"))

    def send_tetragon_event(
        self,
        service_id: str,
        pod_name: str,
        target_path_or_binary: str,
        violation_type: str = "FILESYSTEM_WRITE",
        running_digest: str = "",
        sensor_token: str | None = None,
    ) -> dict[str, Any]:
        """Submit an authenticated eBPF/Tetragon container filesystem write or untracked process event to N3."""
        tok = sensor_token or os.environ.get("WARRANT_TETRAGON_SENSOR_TOKEN") or ""
        return self._request_json(
            "POST",
            "/api/v1/telemetry/tetragon",
            {
                "service_id": service_id,
                "pod_name": pod_name,
                "running_digest": running_digest,
                "violation_type": violation_type,
                "target_path_or_binary": target_path_or_binary,
            },
            bearer_override=tok,
        )

    def simulate(self, scenario: str, signer_bundle: SignerKeyBundle | None = None) -> dict[str, Any]:
        safe_sc = urllib.parse.quote(scenario, safe="")
        return self._request_action_json(
            "POST",
            f"/api/v1/simulate/{safe_sc}",
            "SIMULATION_DRILL",
            {"scenario": scenario},
            payload={},
            signer_bundle=signer_bundle,
        )

    # ------------------------------------------------------------------
    # Exceptions, Estate, Shadow Canary, Containment Bridges & Drift
    # ------------------------------------------------------------------
    def list_exceptions(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/exceptions")

    def resolve_exception(
        self,
        exception_id: str,
        decision: str,
        dsse_envelope: dict[str, Any],
    ) -> dict[str, Any]:
        safe_id = urllib.parse.quote(exception_id, safe="")
        return self._request_json(
            "POST",
            f"/api/v1/exceptions/{safe_id}/resolve",
            {"decision": decision, "dsse_envelope": dsse_envelope},
        )

    def list_estate(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/estate")

    def list_shadow_runs(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/shadow/runs")

    def list_bridges(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/bridges")

    def list_lockouts(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/lockouts")

    def list_drift(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/drift")

    # ------------------------------------------------------------------
    # N4/N5 Attestations, OSCAL 1.1.2, Auditor Vault & Ledger Chains
    # ------------------------------------------------------------------
    def list_attestations(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/attestations")

    def export_oscal_bundle(self, attestation_or_remediation_id: str) -> dict[str, Any]:
        safe_id = urllib.parse.quote(attestation_or_remediation_id, safe="")
        raw = self._request_raw("GET", f"/api/v1/attestations/{safe_id}/oscal")
        return json.loads(raw.decode("utf-8"))

    def mint_auditor_token(
        self,
        label: str = "External 3PAO Assessment",
        scoped_attestation_ids: list[str] | None = None,
        ttl_hours: int = 24,
        signer_bundle: SignerKeyBundle | None = None,
    ) -> dict[str, Any]:
        return self._request_action_json(
            "POST",
            "/api/v1/auditor-tokens",
            "MINT_AUDITOR_TOKEN",
            {
                "auditor_label": label,
                "scoped_attestation_ids": scoped_attestation_ids or [],
                "ttl_hours": ttl_hours,
            },
            payload={
                "label": label,
                "scoped_attestation_ids": scoped_attestation_ids or [],
                "ttl_hours": ttl_hours,
            },
            signer_bundle=signer_bundle,
        )

    def get_auditor_vault(self, bearer_token: str | None = None) -> dict[str, Any]:
        return self._request_json("GET", "/api/v1/auditor/vault", bearer_override=bearer_token)

    def list_agent_actions(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/ledger/actions")

    def verify_ledger_chains(self) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/ledger/verify", {})

    def list_ledger_checkpoints(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/ledger/checkpoints")

    def create_ledger_checkpoint(self, signer_bundle: SignerKeyBundle | None = None) -> dict[str, Any]:
        return self._request_action_json("POST", "/api/v1/ledger/checkpoints", "CREATE_CHECKPOINT", payload={}, signer_bundle=signer_bundle)

    # ------------------------------------------------------------------
    # Live Threat & Scanner Feeds (CISA KEV, Google OSV.dev, Trivy)
    # ------------------------------------------------------------------
    def get_feed_status(self) -> dict[str, Any]:
        return self._request_json("GET", "/api/v1/feeds/status")

    def set_feed_mode(self, mode: str, signer_bundle: SignerKeyBundle | None = None) -> dict[str, Any]:
        st = self.get_feed_status()
        cfg = st["config"]
        cfg["mode"] = mode
        return self._request_action_json("POST", "/api/v1/feeds/config", "FEED_MUTATION", payload=cfg, signer_bundle=signer_bundle)

    def sync_cisa_kev(self, signer_bundle: SignerKeyBundle | None = None) -> dict[str, Any]:
        return self._request_action_json("POST", "/api/v1/feeds/sync/kev", "FEED_MUTATION", payload={}, signer_bundle=signer_bundle)

    def sync_osv(self, auto_ingest: bool = False, signer_bundle: SignerKeyBundle | None = None) -> dict[str, Any]:
        path = "/api/v1/feeds/sync/osv?ingest=true" if auto_ingest else "/api/v1/feeds/sync/osv"
        return self._request_action_json("POST", path, "FEED_MUTATION", payload={}, signer_bundle=signer_bundle)

    def ingest_osv_advisory(
        self, osv_id: str, service_id: str, signer_bundle: SignerKeyBundle | None = None
    ) -> list[dict[str, Any]]:
        return self._request_action_json(
            "POST",
            "/api/v1/feeds/osv/ingest",
            "FEED_MUTATION",
            payload={"osv_id": osv_id, "service_id": service_id},
            signer_bundle=signer_bundle,
        )

    # ------------------------------------------------------------------
    # v1.1.0 Commissioning Functions, Agent Identities & IGA Lifecycle
    # ------------------------------------------------------------------
    def list_commissioning_functions(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/commissioning-functions")

    def list_pending_sponsor_transfers(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/commissioning-functions/pending-transfers")

    def submit_commissioning_function(self, dsse_envelope: dict[str, Any]) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/commissioning-functions", dsse_envelope)

    def transfer_commissioning_sponsor(self, function_id: str, dsse_envelope: dict[str, Any]) -> dict[str, Any]:
        safe_id = urllib.parse.quote(function_id, safe="")
        return self._request_json("POST", f"/api/v1/commissioning-functions/{safe_id}/transfer", dsse_envelope)

    def list_agents(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/agents")

    def enroll_agent(self, dsse_envelope: dict[str, Any]) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/agents/enroll", dsse_envelope)

    def recertify_agent(self, dsse_envelope: dict[str, Any]) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/agents/recertify", dsse_envelope)

    def revoke_agent(self, dsse_envelope: dict[str, Any]) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/agents/revoke", dsse_envelope)

    def exchange_agent_token(self, dsse_envelope: dict[str, Any]) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/agents/token-exchange", dsse_envelope)

    def list_iga_events(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/iga/events")

    def emit_iga_event(
        self,
        event_type: str,
        principal_id: str,
        reason_code: str = "",
        iga_token: str = "",
        hmac_secret: str = "",
        signer_bundle: SignerKeyBundle | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "event_type": event_type,
            "principal_id": principal_id,
        }
        if reason_code:
            payload["reason_code"] = reason_code
        active_signer = signer_bundle or self.signer_bundle
        if active_signer is not None and not iga_token and not hmac_secret:
            return self._request_action_json(
                "POST",
                "/api/v1/iga/events",
                "EMIT_IGA_EVENT",
                {"target_principal_id": principal_id, "iga_event_type": event_type, "reason_code": reason_code},
                payload=payload,
                signer_bundle=active_signer,
            )
        extra: dict[str, str] = {}
        raw_body = json.dumps(payload).encode("utf-8")
        if hmac_secret:
            import hashlib
            import hmac as _hmac

            mac = _hmac.new(hmac_secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
            extra["X-Warrant-IGA-Signature-256"] = f"sha256={mac}"
        if iga_token:
            extra["X-Warrant-IGA-Token"] = iga_token
        raw = self._request_raw("POST", "/api/v1/iga/events", body=raw_body, content_type="application/json", extra_headers=extra or None)
        return json.loads(raw.decode("utf-8"))

    # ------------------------------------------------------------------
    # v1.2.0 WN-7 Finder Translation & WN-8 Distributor Translation
    # ------------------------------------------------------------------
    def submit_finder_intake(
        self,
        vendor: str,
        raw_payload: bytes | str | Path | dict[str, Any],
        target_service: str | None = None,
        distributor_id: str | None = None,
        patch_profile: str | None = None,
        max_findings: int | None = None,
    ) -> list[dict[str, Any]]:
        """Submit Qualys VMDR (XML/JSON), Tenable.io/sc (JSON), or Rapid7 InsightVM (JSON) findings via WN-7."""
        slug = vendor.strip().lower()
        alias_map = {
            "qualys": "qualys",
            "qualys_vmdr": "qualys",
            "tenable": "tenable",
            "tenable_io_sc": "tenable",
            "tenable.io": "tenable",
            "tenable.sc": "tenable",
            "rapid7": "rapid7",
            "rapid7_insightvm": "rapid7",
        }
        if slug not in alias_map:
            raise ValueError(f"Unsupported finder vendor {vendor!r}; expected qualys, tenable, or rapid7")
        slug = alias_map[slug]

        if isinstance(raw_payload, Path):
            raw = raw_payload.read_bytes()
        elif isinstance(raw_payload, dict):
            raw = json.dumps(raw_payload).encode("utf-8")
        elif isinstance(raw_payload, str):
            raw = raw_payload.encode("utf-8")
        else:
            raw = raw_payload

        params: dict[str, str] = {}
        if target_service:
            params["target_service"] = target_service
        if distributor_id:
            params["distributor_id"] = distributor_id
        if patch_profile:
            params["patch_profile"] = patch_profile
        if max_findings and max_findings > 0:
            params["max_findings"] = str(max_findings)

        path = f"/api/v1/intake/{slug}"
        if params:
            path += "?" + urllib.parse.urlencode(params)
        content_type = "application/xml" if raw.lstrip().startswith(b"<") else "application/json"
        resp = self._request_raw("POST", path, body=raw, content_type=content_type)
        return json.loads(resp.decode("utf-8"))

    def list_asset_aliases(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/finders/aliases")

    def upsert_asset_alias(
        self,
        alias: dict[str, Any],
        signer_bundle: SignerKeyBundle | None = None,
    ) -> dict[str, Any]:
        return self._request_action_json(
            "POST",
            "/api/v1/finders/aliases",
            "FEED_MUTATION",
            {},
            payload=alias,
            signer_bundle=signer_bundle,
        )

    def list_distributors(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/distributors")

    def list_deployment_orders(self, remediation_id: str | None = None) -> list[dict[str, Any]]:
        path = "/api/v1/distributors/orders"
        if remediation_id:
            path += "?" + urllib.parse.urlencode({"remediation_id": remediation_id})
        return self._request_json("GET", path)

    def list_deployment_results(self, order_id: str | None = None) -> list[dict[str, Any]]:
        path = "/api/v1/distributors/results"
        if order_id:
            path += "?" + urllib.parse.urlencode({"order_id": order_id})
        return self._request_json("GET", path)

    def dispatch_distributor_order(
        self,
        request: dict[str, Any],
        signer_bundle: SignerKeyBundle | None = None,
    ) -> dict[str, Any]:
        return self._request_action_json(
            "POST",
            "/api/v1/distributors/dispatch",
            "FEED_MUTATION",
            {},
            payload=request,
            signer_bundle=signer_bundle,
        )

    def rollback_distributor_order(
        self,
        order_id: str,
        reason_code: str = "OPERATOR_DISTRIBUTOR_ROLLBACK",
        signer_bundle: SignerKeyBundle | None = None,
    ) -> dict[str, Any]:
        safe_id = urllib.parse.quote(order_id, safe="")
        return self._request_action_json(
            "POST",
            f"/api/v1/distributors/orders/{safe_id}/rollback",
            "EMERGENCY_ROLLBACK",
            {"reason_code": reason_code},
            payload={"reason_code": reason_code},
            signer_bundle=signer_bundle,
        )

    def bind_remediation_class(
        self,
        remediation_id: str,
        warrant_id: str | None = None,
        warrant_envelope: dict[str, Any] | None = None,
        distributor_id: str | None = None,
        auto_execute: bool = False,
    ) -> dict[str, Any]:
        safe_id = urllib.parse.quote(remediation_id, safe="")
        body: dict[str, Any] = {"auto_execute": auto_execute}
        if warrant_id:
            body["warrant_id"] = warrant_id
        if warrant_envelope is not None:
            body["warrant_envelope"] = warrant_envelope
        if distributor_id:
            body["distributor_id"] = distributor_id
        return self._request_json("POST", f"/api/v1/remediations/{safe_id}/bind-class", payload=body)

    def list_estate_sources(self) -> list[dict[str, Any]]:
        return self._request_json("GET", "/api/v1/estate-loader/sources")

    def propose_estate_class(
        self,
        source_system: str,
        scope_services: list[str],
        warrant_class: str = "KEV-TIER1-STATELESS",
        corroborating_scanner: str | None = None,
        estate_drift_policy: str | None = None,
        estate_drift_tolerance_pct: float | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "source_system": source_system,
            "warrant_class": warrant_class,
            "scope_services": scope_services,
        }
        if corroborating_scanner:
            body["corroborating_scanner"] = corroborating_scanner
        if estate_drift_policy:
            body["estate_drift_policy"] = estate_drift_policy
        if estate_drift_tolerance_pct is not None and estate_drift_tolerance_pct > 0:
            body["estate_drift_tolerance_pct"] = estate_drift_tolerance_pct
        return self._request_json("POST", "/api/v1/estate-loader/propose", payload=body)

    def list_estate_evidence(
        self,
        source_system: str | None = None,
        warrant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, str] = {}
        if source_system:
            params["source_system"] = source_system
        if warrant_id:
            params["warrant_id"] = warrant_id
        path = "/api/v1/estate-loader/evidence"
        if params:
            path += "?" + urllib.parse.urlencode(params)
        return self._request_json("GET", path)
