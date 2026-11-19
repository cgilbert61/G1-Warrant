"""RFC 8785 JCS Canonicalizer, DSSEv1 PAE Builder & Offline Ed25519 Verifier for G1-Warrant."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

ROLE_SERVICE_OWNER = "SERVICE_OWNER"
ROLE_AUTHORIZING_OFFICIAL = "AUTHORIZING_OFFICIAL"

PAYLOAD_TYPE_WARRANT = "application/vnd.g1163rt.warrant.v1+json"
PAYLOAD_TYPE_THAW = "application/vnd.g1163rt.freeze-thaw.v1+json"
PAYLOAD_TYPE_EXCEPTION = "application/vnd.g1163rt.exception-resolution.v1+json"
PAYLOAD_TYPE_ATTESTATION = "application/vnd.g1163rt.oscal-attestation.v1+json"


def sha256_hex(data: bytes) -> str:
    """Compute lowercase hexadecimal SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def canonicalize_jcs(obj: Any) -> bytes:
    """Serialize a JSON-compatible Python value into deterministic RFC 8785 JCS UTF-8 bytes."""
    return _jcs_str(obj).encode("utf-8")


def _jcs_str(val: Any) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        if val == 0.0:
            return "0"
        if val.is_integer() and abs(val) < 1e15:
            return str(int(val))
        return json.dumps(val, allow_nan=False)
    if isinstance(val, str):
        return json.dumps(val, ensure_ascii=False)
    if isinstance(val, (list, tuple)):
        return "[" + ",".join(_jcs_str(item) for item in val) + "]"
    if isinstance(val, dict):
        # RFC 8785 lexicographical sort by UTF-16 code units
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
        seed = raw_priv[:32]  # Go ed25519.PrivateKey stores 64 bytes (32-byte seed || 32-byte pubkey)
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


def draft_warrant_envelope(
    scope_services: list[str],
    warrant_class: str = "KEV-TIER1-STATELESS",
    max_cvss: float = 10.0,
    kev_eligible: bool = True,
    max_blast_radius_replicas: int = 8,
    allow_stateful_patches: bool = False,
    sla_bridge_minutes: int = 60,
    max_p99_latency_ms: float = 120.0,
    ttl_days: int = 30,
    warrant_id: str | None = None,
) -> dict[str, Any]:
    """Create an unsigned DSSEv1 Standing Warrant envelope ready for 2-of-2 AC-5 co-signing."""
    if not scope_services:
        raise ValueError("scope_services must contain at least one service ID or '*'")
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=ttl_days)
    payload = {
        "warrant_id": warrant_id or f"wrt-{uuid.uuid4().hex[:8]}",
        "warrant_class": warrant_class,
        "scope_services": scope_services,
        "max_cvss": max_cvss,
        "kev_eligible": kev_eligible,
        "max_blast_radius_replicas": max_blast_radius_replicas,
        "allow_stateful_patches": allow_stateful_patches,
        "sla_bridge_minutes": sla_bridge_minutes,
        "max_p99_latency_ms": max_p99_latency_ms,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return draft_unsigned_envelope(PAYLOAD_TYPE_WARRANT, payload)


def draft_thaw_envelope() -> dict[str, Any]:
    """Create an unsigned DSSEv1 emergency fleet-thaw envelope."""
    return draft_unsigned_envelope(
        PAYLOAD_TYPE_THAW,
        {
            "action": "THAW_FLEET",
            "requested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )


def draft_exception_envelope(exception_record: dict[str, Any]) -> dict[str, Any]:
    """Create an unsigned DSSEv1 ceiling-exception resolution envelope."""
    return draft_unsigned_envelope(
        PAYLOAD_TYPE_EXCEPTION,
        {
            "exception_id": exception_record["exception_id"],
            "remediation_id": exception_record["remediation_id"],
            "service_id": exception_record["service_id"],
            "cve_id": exception_record["cve_id"],
            "evaluated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )


def verify_oscal_bundle_offline(bundle: bytes | str | dict[str, Any], kernel_public_key_b64: str) -> dict[str, Any]:
    """Verify a signed NIST OSCAL 1.1.2 POA&M bundle offline against the Kernel Ed25519 public key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if isinstance(bundle, (bytes, str)):
        doc = json.loads(bundle)
    else:
        doc = bundle

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

    return {
        "valid": True,
        "attestation_id": doc.get("attestation_id", ""),
        "cve_id": doc.get("cve_id", ""),
        "service_id": doc.get("service_id", ""),
        "warrant_id": doc.get("warrant_id", ""),
        "jcs_canonical_match": True,
        "payload_sha256": sha256_hex(raw_payload),
        "pae_sha256": sha256_hex(pae),
        "signer_key_id": sigs[0].get("keyid", ""),
        "entry_hash": doc.get("entry_hash", ""),
    }
