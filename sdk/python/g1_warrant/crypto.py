"""RFC 8785 JCS Canonicalizer, DSSEv1 PAE Builder & Offline Ed25519 Verifier for G1-Warrant."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROLE_SERVICE_OWNER = "SERVICE_OWNER"
ROLE_AUTHORIZING_OFFICIAL = "AUTHORIZING_OFFICIAL"

PAYLOAD_TYPE_WARRANT = "application/vnd.g1163rt.warrant.v1+json"
PAYLOAD_TYPE_THAW = "application/vnd.g1163rt.freeze-thaw.v1+json"
PAYLOAD_TYPE_EXCEPTION = "application/vnd.g1163rt.exception-resolution.v1+json"
PAYLOAD_TYPE_ATTESTATION = "application/vnd.g1163rt.oscal-attestation.v1+json"
PAYLOAD_TYPE_TASK_WARRANT = "application/vnd.g1163rt.task-warrant.v1+json"
PAYLOAD_TYPE_AGENT_TOKEN_EXCHANGE = "application/vnd.g1163rt.agent-token-exchange.v1+json"
PAYLOAD_TYPE_PRINCIPAL_GOVERNANCE = "application/vnd.g1163rt.principal-governance.v1+json"


def sha256_hex(data: bytes) -> str:
    """Compute lowercase hexadecimal SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def canonicalize_jcs(obj: Any) -> bytes:
    """Serialize a JSON-compatible Python value into deterministic RFC 8785 JCS UTF-8 bytes."""
    return _jcs_str(obj).encode("utf-8")


def _format_jcs_float(val: float) -> str:
    """Format an IEEE-754 binary64 number strictly per RFC 8785 Section 3.2.2.3 (ECMA-262 Number::toString)."""
    import math

    if math.isnan(val) or math.isinf(val):
        raise ValueError("RFC 8785 JCS prohibits NaN or Infinity")
    if val == 0.0:
        return "0"
    if val < 0.0:
        return "-" + _format_jcs_float(-val)

    raw = repr(float(val)).lower()
    if "e" in raw:
        mant_str, exp_str = raw.split("e", 1)
        exp = int(exp_str)
    else:
        mant_str, exp = raw, 0

    if "." in mant_str:
        int_part, frac_part = mant_str.split(".", 1)
        digits = int_part + frac_part
        dec_exp = exp - len(frac_part)
    else:
        digits = mant_str
        dec_exp = exp

    digits = digits.lstrip("0")
    stripped_right = len(digits) - len(digits.rstrip("0"))
    if stripped_right > 0:
        digits = digits.rstrip("0")
        dec_exp += stripped_right

    k = len(digits)
    n = dec_exp + k

    if k <= n <= 21:
        return digits + ("0" * (n - k))
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + ("0" * (-n)) + digits

    exp_val = n - 1
    sign = "+" if exp_val >= 0 else "-"
    exp_digits = str(abs(exp_val))
    if k == 1:
        return f"{digits}e{sign}{exp_digits}"
    return f"{digits[0]}.{digits[1:]}e{sign}{exp_digits}"


def _jcs_str(val: Any) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        if -9007199254740991 <= val <= 9007199254740991:
            return str(val)
        return _format_jcs_float(float(val))
    if isinstance(val, float):
        return _format_jcs_float(val)
    if isinstance(val, str):
        return json.dumps(val, ensure_ascii=False)
    if isinstance(val, (list, tuple)):
        return "[" + ",".join(_jcs_str(item) for item in val) + "]"
    if isinstance(val, dict):
        sorted_keys = sorted(val.keys(), key=lambda k: str(k).encode("utf-16-be"))
        members = [f"{json.dumps(str(k), ensure_ascii=False)}:{_jcs_str(val[k])}" for k in sorted_keys]
        return "{" + ",".join(members) + "}"
    raise TypeError(f"Unsupported type for RFC 8785 JCS canonicalization: {type(val)!r}")


def dsse_pae(payload_type: str, raw_payload: bytes) -> bytes:
    """Construct DSSEv1 Pre-Authentication Encoding (PAE) bytes."""
    pt_bytes = payload_type.encode("utf-8")
    prefix = f"DSSEv1 {len(pt_bytes)} ".encode("ascii") + pt_bytes + f" {len(raw_payload)} ".encode("ascii")
    return prefix + raw_payload


def _decode_b64_any(s: str) -> bytes:
    padded = s.strip()
    rem = len(padded) % 4
    if rem:
        padded += "=" * (4 - rem)
    if "-" in padded or "_" in padded:
        return base64.urlsafe_b64decode(padded)
    return base64.b64decode(padded)


@dataclasses.dataclass
class PublicIdentityBundle:
    """Non-custodial public identity manifest (<name>.pub.json) with zero private key material."""

    principal_id: str
    email: str
    display_name: str
    role: str
    key_id: str
    alg: str
    public_key_b64: str
    key_fingerprint: str
    created_at: str

    def to_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PublicIdentityBundle:
        for k in d:
            lk = str(k).lower().strip()
            if "private_key" in lk or "priv_key" in lk or lk == "seed_hex" or "secret_key" in lk:
                raise ValueError(
                    f"PRIVATE_KEY_REJECTED_CLIENT_SIDE: field {k!r} found; pass <name>.pub.json instead of <name>.priv.json"
                )
        return cls(
            principal_id=str(d["principal_id"]),
            email=str(d["email"]),
            display_name=str(d.get("display_name", d["principal_id"])),
            role=str(d["role"]),
            key_id=str(d.get("key_id", "")),
            alg=str(d.get("alg", "Ed25519")),
            public_key_b64=str(d["public_key_b64"]),
            key_fingerprint=str(d.get("key_fingerprint", "")),
            created_at=str(d.get("created_at", "")),
        )


@dataclasses.dataclass
class SignerKeyBundle:
    """Portable Ed25519 AC-5 signing identity compatible with Go's warrantsdk.SignerKeyBundle."""

    principal_id: str
    email: str
    display_name: str
    role: str
    key_id: str
    alg: str
    public_key_b64: str
    private_key_b64: str
    key_fingerprint: str
    created_at: str

    def to_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)

    def to_public_identity(self) -> PublicIdentityBundle:
        return PublicIdentityBundle(
            principal_id=self.principal_id,
            email=self.email,
            display_name=self.display_name,
            role=self.role,
            key_id=self.key_id,
            alg=self.alg,
            public_key_b64=self.public_key_b64,
            key_fingerprint=self.key_fingerprint,
            created_at=self.created_at,
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SignerKeyBundle:
        return cls(
            principal_id=str(d["principal_id"]),
            email=str(d["email"]),
            display_name=str(d.get("display_name", d["principal_id"])),
            role=str(d["role"]),
            key_id=str(d["key_id"]),
            alg=str(d.get("alg", "Ed25519")),
            public_key_b64=str(d["public_key_b64"]),
            private_key_b64=str(d["private_key_b64"]),
            key_fingerprint=str(d["key_fingerprint"]),
            created_at=str(d.get("created_at", "")),
        )

    def sign_envelope(self, slot: int, envelope: dict[str, Any]) -> dict[str, Any]:
        """Append an Ed25519 signature over DSSEv1 PAE bytes in Slot 1 or Slot 2."""
        if slot not in (1, 2):
            raise ValueError(f"AC-5 slot must be 1 (SERVICE_OWNER) or 2 (AUTHORIZING_OFFICIAL), got {slot}")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        raw_priv = _decode_b64_any(self.private_key_b64)
        seed = raw_priv[:32]
        priv_key = Ed25519PrivateKey.from_private_bytes(seed)

        raw_payload = _decode_b64_any(envelope["payload"])
        pae = dsse_pae(envelope["payloadType"], raw_payload)
        sig_bytes = priv_key.sign(pae)

        sigs = list(envelope.get("signatures") or [])
        sigs.append(
            {
                "slot": slot,
                "keyid": self.key_id,
                "alg": "Ed25519",
                "role": self.role,
                "principal_id": self.principal_id,
                "principal_email": self.email,
                "key_fingerprint": self.key_fingerprint,
                "sig": base64.b64encode(sig_bytes).decode("ascii"),
                "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
        envelope["signatures"] = sigs
        return envelope


def resolve_split_key_paths(out_prefix: str | Path) -> tuple[Path, Path]:
    base = str(out_prefix).strip()
    for suf in (".priv.json", ".pub.json", ".json"):
        if base.lower().endswith(suf):
            base = base[: -len(suf)]
            break
    if not base:
        base = "signer"
    return Path(f"{base}.priv.json"), Path(f"{base}.pub.json")


def write_split_keypair_files(out_prefix: str | Path, bundle: SignerKeyBundle) -> tuple[Path, Path]:
    """Write <name>.priv.json (0600 on POSIX) and <name>.pub.json (0644, public-only)."""
    priv_path, pub_path = resolve_split_key_paths(out_prefix)
    priv_text = json.dumps(bundle.to_dict(), indent=2)
    pub_text = json.dumps(bundle.to_public_identity().to_dict(), indent=2)

    if os.name != "nt":
        fd = os.open(str(priv_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, priv_text.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(priv_path, 0o600)
        mode = stat.S_IMODE(priv_path.stat().st_mode)
        if mode != 0o600:
            raise PermissionError(f"Expected 0600 permissions on {priv_path}, got {oct(mode)}")
    else:
        priv_path.write_text(priv_text, encoding="utf-8")

    pub_path.write_text(pub_text, encoding="utf-8")
    if os.name != "nt":
        os.chmod(pub_path, 0o644)
    return priv_path, pub_path


def load_public_identity_file(path_or_text: str | Path | bytes) -> PublicIdentityBundle:
    """Load <name>.pub.json and strictly reject any file containing private_key* fields."""
    if isinstance(path_or_text, Path):
        raw_str = path_or_text.read_text(encoding="utf-8")
    elif isinstance(path_or_text, bytes):
        raw_str = path_or_text.decode("utf-8")
    else:
        raw_str = path_or_text
    data = json.loads(raw_str)
    if not isinstance(data, dict):
        raise ValueError("Expected JSON object in public identity file")
    return PublicIdentityBundle.from_dict(data)


def generate_ed25519_signer_bundle(
    principal_id: str,
    email: str,
    display_name: str,
    role: str = ROLE_SERVICE_OWNER,
) -> SignerKeyBundle:
    """Generate a new Ed25519 AC-5 signing key bundle compatible with both Go and Python SDKs."""
    if role not in (ROLE_SERVICE_OWNER, ROLE_AUTHORIZING_OFFICIAL):
        raise ValueError(f"role must be {ROLE_SERVICE_OWNER} or {ROLE_AUTHORIZING_OFFICIAL}")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    go_compat_priv = seed + pub
    fp = sha256_hex(pub)
    return SignerKeyBundle(
        principal_id=principal_id,
        email=email,
        display_name=display_name,
        role=role,
        key_id=f"ed25519-{principal_id}-{fp[:10]}",
        alg="Ed25519",
        public_key_b64=base64.b64encode(pub).decode("ascii"),
        private_key_b64=base64.b64encode(go_compat_priv).decode("ascii"),
        key_fingerprint=fp,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def draft_unsigned_envelope(payload_type: str, payload_obj: Any) -> dict[str, Any]:
    """Wrap payload_obj in an unsigned DSSEv1 envelope over RFC 8785 JCS UTF-8 bytes."""
    canon = canonicalize_jcs(payload_obj)
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(canon).decode("ascii"),
        "signatures": [],
    }


def draft_governance_envelope(
    action: str,
    fields: dict[str, Any] | None = None,
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    """Create an unsigned Principal Governance DSSEv1 envelope with single-use envelope_id and <=15m TTL."""
    if ttl_seconds <= 0 or ttl_seconds > 900:
        ttl_seconds = 300
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=ttl_seconds)
    payload: dict[str, Any] = dict(fields or {})
    payload.setdefault("envelope_id", f"gov-{uuid.uuid4()}")
    payload["action"] = action
    payload["issued_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    payload["expires_at"] = exp.strftime("%Y-%m-%dT%H:%M:%SZ")
    return draft_unsigned_envelope(PAYLOAD_TYPE_PRINCIPAL_GOVERNANCE, payload)


def draft_principal_enroll_envelope(
    public_identity: PublicIdentityBundle | SignerKeyBundle | dict[str, Any],
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    """Create an unsigned 2-of-2 DSSE Principal Governance envelope (ENROLL_PRINCIPAL) for post-seal enrollment."""
    if isinstance(public_identity, SignerKeyBundle):
        pub = public_identity.to_public_identity().to_dict()
    elif isinstance(public_identity, PublicIdentityBundle):
        pub = public_identity.to_dict()
    else:
        pub = PublicIdentityBundle.from_dict(dict(public_identity)).to_dict()
    return draft_governance_envelope(
        "ENROLL_PRINCIPAL",
        {
            "principal_id": pub["principal_id"],
            "email": pub["email"],
            "display_name": pub.get("display_name", ""),
            "role": pub["role"],
            "key_id": pub.get("key_id", ""),
            "alg": pub.get("alg", "Ed25519"),
            "public_key_b64": pub["public_key_b64"],
        },
        ttl_seconds=ttl_seconds,
    )


def draft_principal_revoke_envelope(
    target_principal_id: str = "",
    target_key_fingerprint: str = "",
    reason_code: str = "SDK_KEY_REVOCATION",
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    """Create an unsigned 1-of-2 DSSE Principal Governance envelope (REVOKE_PRINCIPAL)."""
    if ttl_seconds <= 0 or ttl_seconds > 300:
        ttl_seconds = 300
    fields: dict[str, Any] = {
        "http_method": "POST",
        "canonical_path": "/api/v1/principals/revoke",
        "reason_code": reason_code or "SDK_KEY_REVOCATION",
    }
    if target_principal_id:
        fields["target_principal_id"] = target_principal_id
    if target_key_fingerprint:
        fields["target_key_fingerprint"] = target_key_fingerprint
    return draft_governance_envelope("REVOKE_PRINCIPAL", fields, ttl_seconds=ttl_seconds)


def draft_principal_rotate_and_revoke_envelope(
    replacement_public_identity: PublicIdentityBundle | SignerKeyBundle | dict[str, Any],
    target_principal_id: str = "",
    target_key_fingerprint: str = "",
    reason_code: str = "ATOMIC_DUAL_KEY_ROTATION_AND_REVOCATION",
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    """Create an unsigned atomic 2-of-2 DSSE Principal Governance envelope (ROTATE_AND_REVOKE_PRINCIPAL)."""
    if isinstance(replacement_public_identity, SignerKeyBundle):
        pub = replacement_public_identity.to_public_identity().to_dict()
    elif isinstance(replacement_public_identity, PublicIdentityBundle):
        pub = replacement_public_identity.to_dict()
    else:
        pub = PublicIdentityBundle.from_dict(dict(replacement_public_identity)).to_dict()
    fields: dict[str, Any] = {
        "principal_id": pub["principal_id"],
        "email": pub["email"],
        "display_name": pub.get("display_name", ""),
        "role": pub["role"],
        "key_id": pub.get("key_id", ""),
        "alg": pub.get("alg", "Ed25519"),
        "public_key_b64": pub["public_key_b64"],
        "reason_code": reason_code or "ATOMIC_DUAL_KEY_ROTATION_AND_REVOCATION",
    }
    if target_principal_id:
        fields["target_principal_id"] = target_principal_id
    if target_key_fingerprint:
        fields["target_key_fingerprint"] = target_key_fingerprint
    return draft_governance_envelope("ROTATE_AND_REVOKE_PRINCIPAL", fields, ttl_seconds=ttl_seconds)


def draft_warrant_envelope(
    scope_services: list[str],
    warrant_class: str = "KEV-TIER1-STATELESS",
    max_cvss: float = 10.0,
    kev_eligible: bool = True,
    max_blast_radius_replicas: int = 8,
    allow_stateful_patches: bool = False,
    allow_secret_rotation: bool = False,
    auto_remediate_cwes: list[str] | None = None,
    sla_bridge_minutes: int = 60,
    max_p99_latency_ms: float = 120.0,
    ttl_days: int = 30,
    warrant_id: str | None = None,
    scope_assets: list[str] | None = None,
    authorized_vendor_detections: list[str] | None = None,
) -> dict[str, Any]:
    """Create an unsigned DSSEv1 Standing Warrant envelope ready for 2-of-2 AC-5 co-signing."""
    if not scope_services:
        raise ValueError("scope_services must contain at least one service ID or '*'")
    if warrant_class == "SECRET-ROTATION-STATELESS":
        allow_secret_rotation = True
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=ttl_days)
    payload: dict[str, Any] = {
        "warrant_id": warrant_id or f"wrt-{uuid.uuid4().hex[:8]}",
        "warrant_class": warrant_class,
        "scope_services": scope_services,
        "max_cvss": max_cvss,
        "kev_eligible": kev_eligible,
        "max_blast_radius_replicas": max_blast_radius_replicas,
        "allow_stateful_patches": allow_stateful_patches,
        "allow_secret_rotation": allow_secret_rotation,
        "sla_bridge_minutes": sla_bridge_minutes,
        "max_p99_latency_ms": max_p99_latency_ms,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if scope_assets:
        payload["scope_assets"] = scope_assets
    if authorized_vendor_detections:
        payload["authorized_vendor_detections"] = authorized_vendor_detections
    if auto_remediate_cwes:
        payload["auto_remediate_cwes"] = auto_remediate_cwes
    return draft_unsigned_envelope(PAYLOAD_TYPE_WARRANT, payload)


def draft_thaw_envelope(freeze_epoch: int = 2, ttl_seconds: int = 900) -> dict[str, Any]:
    """Create an unsigned DSSEv1 emergency fleet-thaw envelope bound to a monotonic freeze_epoch and single-use envelope_id."""
    if ttl_seconds <= 0 or ttl_seconds > 900:
        ttl_seconds = 900
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=ttl_seconds)
    return draft_unsigned_envelope(
        PAYLOAD_TYPE_THAW,
        {
            "envelope_id": f"thaw-{uuid.uuid4()}",
            "action": "THAW",
            "freeze_epoch": int(freeze_epoch),
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )


def draft_exception_envelope(exception_record: dict[str, Any], ttl_seconds: int = 900) -> dict[str, Any]:
    """Create an unsigned DSSEv1 ceiling-exception resolution envelope bound to exception_id and single-use envelope_id."""
    if ttl_seconds <= 0 or ttl_seconds > 900:
        ttl_seconds = 900
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=ttl_seconds)
    return draft_unsigned_envelope(
        PAYLOAD_TYPE_EXCEPTION,
        {
            "envelope_id": f"exc-{uuid.uuid4()}",
            "exception_id": exception_record["exception_id"],
            "remediation_id": exception_record.get("remediation_id", ""),
            "service_id": exception_record.get("service_id", ""),
            "cve_id": exception_record.get("cve_id", ""),
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )


TRUST_BASIS_EXTERNAL_PINNED_PUBKEY = "EXTERNAL_PINNED_PUBKEY"
TRUST_BASIS_EXTERNAL_KEYRING = "EXTERNAL_KEYRING"
TRUST_BASIS_EMBEDDED_KEYRING_OPT_IN = "EMBEDDED_BUNDLE_KEYRING_UNTRUSTED_OPT_IN"


def _extract_and_reconcile_signed_attestation_identity(
    parsed_payload: Any,
    outer_doc: dict[str, Any],
) -> tuple[str, str, str, str]:
    if not isinstance(parsed_payload, dict):
        raise ValueError("SIGNED_PAYLOAD_MISSING_IDENTITY_CLAIMS: signed payload must be a JSON object")

    def _find_prop(obj: Any, prop_name: str) -> str:
        if not isinstance(obj, dict):
            return ""
        props = obj.get("props")
        if not isinstance(props, list):
            return ""
        for item in props:
            if isinstance(item, dict) and item.get("name") == prop_name:
                val = str(item.get("value", "")).strip()
                if val:
                    return val
        return ""

    att_id = ""
    cve_id = ""
    svc_id = ""
    warrant_id = ""

    poam = parsed_payload.get("plan-of-action-and-milestones")
    if isinstance(poam, dict):
        att_id = _find_prop(poam.get("metadata"), "attestation-id")
        ld = poam.get("local-definitions")
        if isinstance(ld, dict):
            for inv_item in ld.get("inventory-items") or []:
                found = _find_prop(inv_item, "service-id")
                if found:
                    svc_id = found
                    break
        for obs in poam.get("observations") or []:
            found = _find_prop(obs, "warrant-id")
            if found:
                warrant_id = found
                break
        for risk in poam.get("risks") or []:
            found = _find_prop(risk, "cve-id")
            if found:
                cve_id = found
                break
    else:
        att_id = str(parsed_payload.get("attestation_id", "")).strip()
        cve_id = str(parsed_payload.get("cve_id", "")).strip()
        svc_id = str(parsed_payload.get("service_id", "")).strip()
        warrant_id = str(parsed_payload.get("warrant_id", "")).strip()

    if not att_id or not cve_id or not svc_id:
        raise ValueError(
            f"SIGNED_PAYLOAD_MISSING_IDENTITY_CLAIMS: signed payload must declare attestation_id ({att_id!r}), "
            f"cve_id ({cve_id!r}), and service_id ({svc_id!r})"
        )

    for field_name, signed_val in (
        ("attestation_id", att_id),
        ("cve_id", cve_id),
        ("service_id", svc_id),
        ("warrant_id", warrant_id),
    ):
        outer_val = str(outer_doc.get(field_name, "") or "").strip()
        if outer_val and outer_val != signed_val:
            raise ValueError(
                f"UNSIGNED_WRAPPER_MISMATCH: outer {field_name} {outer_val!r} does not match signed payload {signed_val!r}"
            )

    return att_id, cve_id, svc_id, warrant_id


def verify_oscal_bundle_offline(bundle: bytes | str | dict[str, Any], kernel_public_key_b64: str) -> dict[str, Any]:
    """Verify a signed NIST OSCAL 1.1.2 POA&M bundle offline against a pinned Kernel Ed25519 public key (WN-3/WN-4)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    doc = json.loads(bundle) if isinstance(bundle, (bytes, str)) else bundle
    env = doc["dsse_envelope"]
    raw_payload = _decode_b64_any(env["payload"])
    parsed_payload = json.loads(raw_payload.decode("utf-8"))
    recanon = canonicalize_jcs(parsed_payload)
    if raw_payload != recanon:
        raise ValueError("RFC 8785 JCS canonicalization mismatch: payload bytes are not canonical")

    sigs = env.get("signatures") or []
    if not sigs:
        raise ValueError("DSSE envelope contains zero signatures")

    pae = dsse_pae(env["payloadType"], raw_payload)
    pub_bytes = _decode_b64_any(kernel_public_key_b64)
    pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    sig_bytes = _decode_b64_any(sigs[0]["sig"])
    try:
        pub_key.verify(sig_bytes, pae)
    except InvalidSignature as exc:
        raise ValueError("Ed25519 signature verification FAILED over DSSEv1 PAE") from exc

    signed_att_id, signed_cve_id, signed_svc_id, signed_warrant_id = _extract_and_reconcile_signed_attestation_identity(
        parsed_payload, doc
    )

    return {
        "valid": True,
        "trust_basis": TRUST_BASIS_EXTERNAL_PINNED_PUBKEY,
        "attestation_id": signed_att_id,
        "cve_id": signed_cve_id,
        "service_id": signed_svc_id,
        "warrant_id": signed_warrant_id,
        "jcs_canonical_match": True,
        "payload_sha256": sha256_hex(raw_payload),
        "pae_sha256": sha256_hex(pae),
        "signer_key_id": sigs[0].get("keyid", ""),
        "entry_hash": doc.get("entry_hash", ""),
    }


def verify_oscal_bundle_with_keyring(
    bundle: bytes | str | dict[str, Any],
    key_ring: list[dict[str, Any]] | None = None,
    *,
    allow_embedded_keyring_opt_in: bool = False,
) -> dict[str, Any]:
    """Verify a signed NIST OSCAL 1.1.2 POA&M bundle against an explicit Kernel Ed25519 public-key ring.

    Fails closed when key_ring is omitted or empty unless allow_embedded_keyring_opt_in=True is explicitly passed (WN-4).
    """
    doc = json.loads(bundle) if isinstance(bundle, (bytes, str)) else bundle
    sigs = (doc.get("dsse_envelope") or {}).get("signatures") or []
    if not sigs:
        raise ValueError("DSSE envelope contains zero signatures")
    target_kid = sigs[0].get("keyid", "")

    if key_ring and len(key_ring) > 0:
        candidates = key_ring
        trust_basis = TRUST_BASIS_EXTERNAL_KEYRING
    else:
        if not allow_embedded_keyring_opt_in:
            raise ValueError(
                "UNTRUSTED_KEYRING_EMPTY: external key_ring is required; embedded bundle kernel_public_key_ring is "
                "untrusted unless allow_embedded_keyring_opt_in=True is explicitly enabled"
            )
        embedded = doc.get("kernel_public_key_ring") or []
        if not embedded:
            raise ValueError(
                "UNTRUSTED_KEYRING_EMPTY: allow_embedded_keyring_opt_in=True enabled, but bundle contains no embedded kernel_public_key_ring"
            )
        candidates = embedded
        trust_basis = TRUST_BASIS_EMBEDDED_KEYRING_OPT_IN

    for entry in candidates:
        if entry.get("key_id") == target_kid:
            res = verify_oscal_bundle_offline(doc, str(entry["public_key_b64"]))
            res["trust_basis"] = trust_basis
            return res
    raise ValueError(
        f"Kernel signing key {target_kid!r} not found in verification public-key ring ({len(candidates)} keys, trust_basis={trust_basis})"
    )


@dataclasses.dataclass
class AgentKeyBundle:
    """Portable Ed25519 workload/agent or builder keypair compatible with Go warrantsdk.AgentKeyBundle."""

    agent_id: str
    display_name: str
    key_id: str
    alg: str
    public_key_b64: str
    private_key_b64: str
    key_fingerprint: str
    created_at: str

    def to_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)

    def sign_envelope(self, envelope: dict[str, Any]) -> dict[str, Any]:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        seed = _decode_b64_any(self.private_key_b64)[:32]
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        raw_payload = _decode_b64_any(envelope["payload"])
        pae = dsse_pae(envelope["payloadType"], raw_payload)
        sig_bytes = priv.sign(pae)
        sigs = list(envelope.get("signatures") or [])
        sigs.append(
            {
                "slot": 1,
                "keyid": self.key_id,
                "alg": "Ed25519",
                "principal_id": self.agent_id,
                "key_fingerprint": self.key_fingerprint,
                "sig": base64.b64encode(sig_bytes).decode("ascii"),
                "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
        envelope["signatures"] = sigs
        return envelope


def generate_agent_key_bundle(agent_id: str, display_name: str = "") -> AgentKeyBundle:
    """Generate a new Ed25519 workload/agent or builder key bundle."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = sha256_hex(pub)
    aid = agent_id.strip()
    return AgentKeyBundle(
        agent_id=aid,
        display_name=(display_name.strip() or aid),
        key_id=f"ed25519-{aid}-{fp[:10]}",
        alg="Ed25519",
        public_key_b64=base64.b64encode(pub).decode("ascii"),
        private_key_b64=base64.b64encode(seed + pub).decode("ascii"),
        key_fingerprint=fp,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def sign_builder_provenance(
    agent_id: str,
    artifact_digest: str,
    agent_public_key_b64: str,
    builder_private_key_b64: str,
) -> str:
    """Sign canonical G1_AGENT_PROVENANCE_V1|{agent_id}|{artifact_digest}|{public_key_b64} with an Ed25519 builder key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = _decode_b64_any(builder_private_key_b64)[:32]
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    preimage = f"G1_AGENT_PROVENANCE_V1|{agent_id.strip()}|{artifact_digest.strip()}|{agent_public_key_b64.strip()}".encode(
        "utf-8"
    )
    return base64.b64encode(priv.sign(preimage)).decode("ascii")


def draft_commissioning_function_envelope(
    function_id: str,
    display_name: str,
    owning_org_unit: str,
    primary_so_principal_id: str,
    primary_ao_principal_id: str,
    escalation_contact: str,
    cost_center: str = "",
    secondary_so_principal_id: str = "",
    secondary_ao_principal_id: str = "",
    orphan_grace_hours: int = 168,
    is_transfer: bool = False,
    reason_code: str = "",
) -> dict[str, Any]:
    """Create an unsigned 2-of-2 DSSE envelope for UPSERT_COMMISSIONING_FUNCTION or TRANSFER_COMMISSIONING_SPONSOR."""
    action = "TRANSFER_COMMISSIONING_SPONSOR" if is_transfer else "UPSERT_COMMISSIONING_FUNCTION"
    fields: dict[str, Any] = {
        "function_id": function_id,
        "display_name": display_name,
        "owning_org_unit": owning_org_unit,
        "cost_center": cost_center,
        "primary_so_principal_id": primary_so_principal_id,
        "secondary_so_principal_id": secondary_so_principal_id,
        "primary_ao_principal_id": primary_ao_principal_id,
        "secondary_ao_principal_id": secondary_ao_principal_id,
        "escalation_contact": escalation_contact,
        "orphan_grace_hours": int(orphan_grace_hours),
    }
    if reason_code:
        fields["reason_code"] = reason_code
    return draft_governance_envelope(action, fields, ttl_seconds=300)


def draft_agent_enroll_envelope(
    agent_id: str,
    commissioning_function_id: str,
    public_key_b64: str,
    artifact_digest: str,
    builder_principal_id: str,
    builder_public_key_b64: str,
    builder_key_fingerprint: str,
    builder_provenance_sig_b64: str,
    allowed_actions: list[str],
    allowed_services: list[str],
    display_name: str = "",
    agent_kind: str = "EXTERNAL_AUTONOMOUS_AGENT",
    allowed_egress_profile: str = "ZERO_EGRESS_ISOLATED",
    max_ttl_seconds: int = 120,
    max_delegation_depth: int = 1,
    allow_autonomous_intake: bool = False,
    recertify_days: int = 30,
    spiffe_id: str = "",
) -> dict[str, Any]:
    """Create an unsigned 2-of-2 ENROLL_AGENT_IDENTITY DSSE envelope."""
    return draft_governance_envelope(
        "ENROLL_AGENT_IDENTITY",
        {
            "agent_id": agent_id,
            "display_name": display_name or agent_id,
            "agent_kind": agent_kind,
            "commissioning_function_id": commissioning_function_id,
            "alg": "Ed25519",
            "public_key_b64": public_key_b64,
            "spiffe_id": spiffe_id,
            "artifact_digest": artifact_digest,
            "builder_principal_id": builder_principal_id,
            "builder_public_key_b64": builder_public_key_b64,
            "builder_key_fingerprint": builder_key_fingerprint,
            "builder_provenance_sig_b64": builder_provenance_sig_b64,
            "allowed_actions": allowed_actions,
            "allowed_services": allowed_services,
            "allowed_egress_profile": allowed_egress_profile,
            "max_ttl_seconds": int(max_ttl_seconds),
            "max_delegation_depth": int(max_delegation_depth),
            "allow_autonomous_intake": bool(allow_autonomous_intake),
            "recertify_days": int(recertify_days),
        },
        ttl_seconds=300,
    )


def draft_agent_recertify_envelope(
    agent_id: str,
    recertify_days: int = 90,
    reason_code: str = "DUAL_KEY_RECERTIFICATION_RENEWAL",
) -> dict[str, Any]:
    """Create an unsigned 2-of-2 RECERTIFY_AGENT_IDENTITY DSSE envelope."""
    return draft_governance_envelope(
        "RECERTIFY_AGENT_IDENTITY",
        {
            "agent_id": agent_id,
            "recertify_days": int(recertify_days),
            "reason_code": reason_code,
        },
        ttl_seconds=300,
    )


def draft_agent_revoke_envelope(
    agent_id: str,
    reason_code: str = "SDK_AGENT_KILL_SWITCH",
) -> dict[str, Any]:
    """Create an unsigned 1-of-2 or self-signed REVOKE_AGENT_IDENTITY DSSE envelope."""
    return draft_governance_envelope(
        "REVOKE_AGENT_IDENTITY",
        {
            "agent_id": agent_id,
            "reason_code": reason_code,
        },
        ttl_seconds=300,
    )


def sign_token_exchange_request(
    caller: AgentKeyBundle,
    target_asset: str,
    requested_action: str,
    authority_mode: str = "WARRANT_DELEGATED_COMPOSITE",
    warrant_id: str = "",
    remediation_id: str = "",
    requested_egress_profile: str = "",
    requested_ttl_seconds: int = 60,
    parent_task_warrant: dict[str, Any] | None = None,
    parent_holder: AgentKeyBundle | None = None,
) -> dict[str, Any]:
    """Draft and sign an RFC 8693 AgentTokenExchangePayload DSSE PoP request (<= 60s TTL)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    now = datetime.now(timezone.utc)
    env_id = f"xch-{uuid.uuid4()}"
    payload: dict[str, Any] = {
        "envelope_id": env_id,
        "agent_id": caller.agent_id,
        "authority_mode": authority_mode,
        "target_asset": target_asset,
        "requested_action": requested_action,
        "requested_ttl_seconds": int(requested_ttl_seconds),
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(seconds=45)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if warrant_id:
        payload["warrant_id"] = warrant_id
    if remediation_id:
        payload["remediation_id"] = remediation_id
    if requested_egress_profile:
        payload["requested_egress_profile"] = requested_egress_profile
    if parent_task_warrant is not None:
        payload["parent_task_warrant"] = parent_task_warrant
        if parent_holder is not None:
            parent_doc = json.loads(_decode_b64_any(parent_task_warrant["payload"]).decode("utf-8"))
            preimage = f"G1_DELEGATE_ACT_V1|{parent_doc['task_token_id']}|{caller.agent_id}|{env_id}".encode("utf-8")
            p_priv = Ed25519PrivateKey.from_private_bytes(_decode_b64_any(parent_holder.private_key_b64)[:32])
            payload["parent_holder_pop_sig_b64"] = base64.b64encode(p_priv.sign(preimage)).decode("ascii")

    env = draft_unsigned_envelope(PAYLOAD_TYPE_AGENT_TOKEN_EXCHANGE, payload)
    return caller.sign_envelope(env)


def build_agent_pop_headers(
    method: str,
    canonical_path: str,
    body: bytes,
    task_warrant_dsse: dict[str, Any],
    holder: AgentKeyBundle,
    unix_ts: int | None = None,
) -> dict[str, str]:
    """Construct wire-level X-Warrant-Task-DSSE and X-Warrant-Agent-PoP headers for an outbound HTTP request."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    ts = int(unix_ts if unix_ts is not None else datetime.now(timezone.utc).timestamp())
    task_payload = json.loads(_decode_b64_any(task_warrant_dsse["payload"]).decode("utf-8"))
    tok_id = str(task_payload["task_token_id"]).strip()
    path_clean = canonical_path.strip() or "/"
    preimage = f"G1_AGENT_POP_V1|{method.strip().upper()}|{path_clean}|{sha256_hex(body)}|{tok_id}|{ts}".encode("utf-8")
    priv = Ed25519PrivateKey.from_private_bytes(_decode_b64_any(holder.private_key_b64)[:32])
    sig_b64 = base64.b64encode(priv.sign(preimage)).decode("ascii")
    return {
        "X-Warrant-Task-DSSE": base64.b64encode(json.dumps(task_warrant_dsse).encode("utf-8")).decode("ascii"),
        "X-Warrant-Agent-PoP": f"{ts}.{sig_b64}",
    }
