"""G1-Warrant Official Python Client SDK & Offline DSSE/OSCAL Toolkit."""

from .client import AuditorScopeViolationError, WarrantAPIError, WarrantClient
from .crypto import (
    PAYLOAD_TYPE_ATTESTATION,
    PAYLOAD_TYPE_EXCEPTION,
    PAYLOAD_TYPE_THAW,
    PAYLOAD_TYPE_WARRANT,
    ROLE_AUTHORIZING_OFFICIAL,
    ROLE_SERVICE_OWNER,
    SignerKeyBundle,
    canonicalize_jcs,
    draft_exception_envelope,
    draft_thaw_envelope,
    draft_warrant_envelope,
    dsse_pae,
    generate_ed25519_signer_bundle,
    verify_oscal_bundle_offline,
    verify_oscal_bundle_with_keyring,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "WarrantClient",
    "WarrantAPIError",
    "AuditorScopeViolationError",
    "SignerKeyBundle",
    "ROLE_SERVICE_OWNER",
    "ROLE_AUTHORIZING_OFFICIAL",
    "PAYLOAD_TYPE_WARRANT",
    "PAYLOAD_TYPE_THAW",
    "PAYLOAD_TYPE_EXCEPTION",
    "PAYLOAD_TYPE_ATTESTATION",
    "canonicalize_jcs",
    "dsse_pae",
    "generate_ed25519_signer_bundle",
    "draft_warrant_envelope",
    "draft_thaw_envelope",
    "draft_exception_envelope",
    "verify_oscal_bundle_offline",
    "verify_oscal_bundle_with_keyring",
]
