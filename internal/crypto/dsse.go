package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	AlgEd25519       = "Ed25519"
	AlgECDSAP256     = "ECDSA-P256"
	AlgWebAuthnES256 = "WebAuthn-ES256"
	AlgWebAuthnEdDSA = "WebAuthn-EdDSA"

	PayloadTypeWarrant             = "application/vnd.g1163rt.warrant.v1+json"
	PayloadTypeThaw                = "application/vnd.g1163rt.freeze-thaw.v1+json"
	PayloadTypeException           = "application/vnd.g1163rt.exception-resolution.v1+json"
	PayloadTypeAttestation         = "application/vnd.g1163rt.oscal-attestation.v1+json"
	PayloadTypeTaskWarrant         = "application/vnd.g1163rt.task-warrant.v1+json"
	PayloadTypePrincipalGovernance = "application/vnd.g1163rt.principal-governance.v1+json"
	PayloadTypeGenesisSeal         = "application/vnd.g1163rt.genesis-seal.v1+json"
	PayloadTypeKernelKeyRotation   = "application/vnd.g1163rt.kernel-key-rotation.v1+json"

	RoleServiceOwner        = "SERVICE_OWNER"
	RoleAuthorizingOfficial = "AUTHORIZING_OFFICIAL"
	RoleSystemAdmin         = "SYSTEM_ADMIN"
	RoleOperator            = "OPERATOR"
	RoleAuditor             = "AUDITOR"
	RoleAttestationKernel   = "ATTESTATION_KERNEL"
)

// Envelope is an RFC/in-toto Dead Simple Signing Envelope (DSSE v1.0).
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64(JCS(payload))
	Signatures  []Signature `json:"signatures"`
}

// Signature represents one cryptographic signature slot inside a DSSE Envelope.
type Signature struct {
	Slot             int               `json:"slot,omitempty"`
	KeyID            string            `json:"keyid"`
	Alg              string            `json:"alg"`
	Role             string            `json:"role,omitempty"`
	PrincipalID      string            `json:"principal_id,omitempty"`
	PrincipalEmail   string            `json:"principal_email,omitempty"`
	KeyFingerprint   string            `json:"key_fingerprint,omitempty"`
	Sig              string            `json:"sig"`
	SignedAt         string            `json:"signed_at,omitempty"`
	WebAuthnMetadata *WebAuthnMetadata `json:"webauthn,omitempty"`
}

// PrincipalKey holds the verified public identity and key material for a signer.
type PrincipalKey struct {
	PrincipalID    string
	Email          string
	DisplayName    string
	Role           string
	KeyID          string
	Alg            string
	PublicKeyBytes []byte // raw 32-byte Ed25519 or SPKI DER
	KeyFingerprint string
	Revoked        bool
	RevokeReason   string
}

// KeyResolver resolves a KeyID to its authoritative PrincipalKey record.
type KeyResolver interface {
	ResolveKey(keyID string) (*PrincipalKey, error)
}

// MapKeyResolver is an in-memory KeyResolver for fast lookups and tests.
type MapKeyResolver map[string]*PrincipalKey

func (m MapKeyResolver) ResolveKey(keyID string) (*PrincipalKey, error) {
	pk, ok := m[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown keyid %q", keyID)
	}
	return pk, nil
}

// PAE constructs the DSSEv1 Pre-Authentication Encoding byte slice:
// "DSSEv1 " + LEN(type) + " " + type + " " + LEN(body) + " " + body
func PAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, 0, len(prefix)+len(payload))
	out = append(out, []byte(prefix)...)
	out = append(out, payload...)
	return out
}

// NewUnsignedEnvelope canonicalizes payloadObj with RFC 8785 JCS and wraps it in a DSSE Envelope.
func NewUnsignedEnvelope(payloadType string, payloadObj any) (*Envelope, []byte, error) {
	canon, err := CanonicalizeStruct(payloadObj)
	if err != nil {
		return nil, nil, err
	}
	return &Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(canon),
		Signatures:  []Signature{},
	}, canon, nil
}

// DecodePayload decodes the DSSE envelope payload bytes.
func (e *Envelope) DecodePayload() ([]byte, error) {
	if e == nil {
		return nil, errors.New("nil dsse envelope")
	}
	return DecodeBase64Any(e.Payload)
}

// SignEd25519 appends an Ed25519 signature over PAE(e.PayloadType, rawPayload) to the envelope.
func (e *Envelope) SignEd25519(slot int, pk PrincipalKey, priv ed25519.PrivateKey) error {
	rawPayload, err := e.DecodePayload()
	if err != nil {
		return err
	}
	pae := PAE(e.PayloadType, rawPayload)
	sig := ed25519.Sign(priv, pae)
	e.Signatures = append(e.Signatures, Signature{
		Slot:           slot,
		KeyID:          pk.KeyID,
		Alg:            AlgEd25519,
		Role:           pk.Role,
		PrincipalID:    pk.PrincipalID,
		PrincipalEmail: pk.Email,
		KeyFingerprint: pk.KeyFingerprint,
		Sig:            base64.StdEncoding.EncodeToString(sig),
		SignedAt:       time.Now().UTC().Format(time.RFC3339),
	})
	return nil
}

// SignECDSAP256 appends an ECDSA-P256 ASN.1 signature over SHA-256(PAE) to the envelope.
func (e *Envelope) SignECDSAP256(slot int, pk PrincipalKey, priv *ecdsa.PrivateKey) error {
	rawPayload, err := e.DecodePayload()
	if err != nil {
		return err
	}
	pae := PAE(e.PayloadType, rawPayload)
	digest := sha256.Sum256(pae)
	sigDER, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return err
	}
	e.Signatures = append(e.Signatures, Signature{
		Slot:           slot,
		KeyID:          pk.KeyID,
		Alg:            AlgECDSAP256,
		Role:           pk.Role,
		PrincipalID:    pk.PrincipalID,
		PrincipalEmail: pk.Email,
		KeyFingerprint: pk.KeyFingerprint,
		Sig:            base64.StdEncoding.EncodeToString(sigDER),
		SignedAt:       time.Now().UTC().Format(time.RFC3339),
	})
	return nil
}

// VerifySingleSignature verifies one DSSE signature against an authoritative PrincipalKey.
func VerifySingleSignature(payloadType string, rawPayload []byte, sig Signature, pk *PrincipalKey, webauthnCfg WebAuthnConfig) error {
	if pk == nil {
		return errors.New("nil principal key")
	}
	if pk.Revoked {
		return fmt.Errorf("REVOKED_PRINCIPAL_OR_KEY: principal %s (%s) key %s is revoked (%s)", pk.PrincipalID, pk.Email, pk.KeyID, pk.RevokeReason)
	}
	if sig.KeyFingerprint != "" && !strings.EqualFold(sig.KeyFingerprint, pk.KeyFingerprint) {
		return fmt.Errorf("key fingerprint mismatch for %s: envelope=%s registry=%s", pk.KeyID, sig.KeyFingerprint, pk.KeyFingerprint)
	}
	if sig.PrincipalID != "" && sig.PrincipalID != pk.PrincipalID {
		return fmt.Errorf("principal_id mismatch for key %s: envelope=%s registry=%s", pk.KeyID, sig.PrincipalID, pk.PrincipalID)
	}
	sigBytes, err := DecodeBase64Any(sig.Sig)
	if err != nil {
		return fmt.Errorf("decode signature bytes: %w", err)
	}
	pae := PAE(payloadType, rawPayload)

	if sig.WebAuthnMetadata != nil || strings.HasPrefix(sig.Alg, "WebAuthn") {
		return VerifyWebAuthnAssertion(pae, sigBytes, sig.WebAuthnMetadata, pk.PublicKeyBytes, webauthnCfg)
	}

	switch sig.Alg {
	case AlgEd25519, "":
		var edPub ed25519.PublicKey
		if len(pk.PublicKeyBytes) == ed25519.PublicKeySize {
			edPub = ed25519.PublicKey(pk.PublicKeyBytes)
		} else {
			parsed, err := x509.ParsePKIXPublicKey(pk.PublicKeyBytes)
			if err != nil {
				return fmt.Errorf("parse ed25519 spki key: %w", err)
			}
			var ok bool
			edPub, ok = parsed.(ed25519.PublicKey)
			if !ok {
				return errors.New("public key is not Ed25519")
			}
		}
		if len(sigBytes) != ed25519.SignatureSize || !ed25519.Verify(edPub, pae, sigBytes) {
			return fmt.Errorf("ed25519 signature verification failed for key %s", pk.KeyID)
		}
		return nil
	case AlgECDSAP256:
		parsed, err := x509.ParsePKIXPublicKey(pk.PublicKeyBytes)
		if err != nil {
			return fmt.Errorf("parse ecdsa p256 public key: %w", err)
		}
		ecPub, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("public key is not ECDSA P-256")
		}
		digest := sha256.Sum256(pae)
		if !ecdsa.VerifyASN1(ecPub, digest[:], sigBytes) {
			return fmt.Errorf("ecdsa p256 signature verification failed for key %s", pk.KeyID)
		}
		return nil
	default:
		return fmt.Errorf("unsupported signature algorithm %q", sig.Alg)
	}
}

// DualHumanVerificationResult captures the verified Slot 1 (Service Owner) and Slot 2 (Authorizing Official) identities.
type DualHumanVerificationResult struct {
	CanonicalPayload []byte
	PayloadSHA256    string
	Slot1            *PrincipalKey
	Slot2            *PrincipalKey
}

// VerifyDualHumanCeremony enforces NIST SP 800-53 AC-5 Separation of Duties + 2-of-2 cryptographic verification:
//   - Exactly or at least 2 distinct human signatures covering Slot 1 (SERVICE_OWNER) and Slot 2 (AUTHORIZING_OFFICIAL)
//   - Rejects SYSTEM_ADMIN principals in any slot
//   - Rejects identical PrincipalID, Email, or KeyFingerprint across Slot 1 and Slot 2
//   - Rejects any revoked key or principal
//   - Verifies JCS canonical integrity of the payload
func VerifyDualHumanCeremony(env *Envelope, expectedPayloadType string, resolver KeyResolver, webauthnCfg WebAuthnConfig) (*DualHumanVerificationResult, error) {
	if env == nil {
		return nil, errors.New("AC5_MISSING_ENVELOPE: nil DSSE envelope")
	}
	if expectedPayloadType != "" && env.PayloadType != expectedPayloadType {
		return nil, fmt.Errorf("DSSE_PAYLOAD_TYPE_MISMATCH: got %q want %q", env.PayloadType, expectedPayloadType)
	}
	if len(env.Signatures) < 2 {
		return nil, fmt.Errorf("AC5_DUAL_SIG_REQUIRED: expected 2 human signatures, got %d", len(env.Signatures))
	}
	rawPayload, err := env.DecodePayload()
	if err != nil {
		return nil, fmt.Errorf("DSSE_PAYLOAD_DECODE_ERR: %w", err)
	}
	canon, err := CanonicalizeJSON(rawPayload)
	if err != nil {
		return nil, fmt.Errorf("DSSE_JCS_INVALID: %w", err)
	}
	if string(canon) != string(rawPayload) {
		return nil, errors.New("DSSE_PAYLOAD_NOT_CANONICAL_JCS: payload bytes deviate from RFC 8785 JCS")
	}

	var slot1Key, slot2Key *PrincipalKey
	var slot1Sig, slot2Sig *Signature
	for idx, sig := range env.Signatures {
		sigCopy := sig
		pk, err := resolver.ResolveKey(sig.KeyID)
		if err != nil {
			return nil, fmt.Errorf("AC5_UNKNOWN_SIGNER (sig %d): %w", idx, err)
		}
		if pk.Role == RoleSystemAdmin || sig.Role == RoleSystemAdmin {
			return nil, fmt.Errorf("AC5_SYSADMIN_PROHIBITED: principal %s (%s) holds SYSTEM_ADMIN role and cannot sign warrants", pk.PrincipalID, pk.Email)
		}
		if err := VerifySingleSignature(env.PayloadType, rawPayload, sig, pk, webauthnCfg); err != nil {
			return nil, fmt.Errorf("DSSE_SIG_INVALID (slot/idx %d): %w", idx+1, err)
		}
		switch {
		case (sig.Slot == 1 || (sig.Slot == 0 && slot1Key == nil && pk.Role == RoleServiceOwner)):
			if pk.Role != RoleServiceOwner {
				return nil, fmt.Errorf("AC5_SLOT1_ROLE_MISMATCH: Slot 1 requires SERVICE_OWNER, got %s (%s)", pk.Role, pk.PrincipalID)
			}
			slot1Key = pk
			slot1Sig = &sigCopy
		case (sig.Slot == 2 || (sig.Slot == 0 && slot2Key == nil && pk.Role == RoleAuthorizingOfficial)):
			if pk.Role != RoleAuthorizingOfficial {
				return nil, fmt.Errorf("AC5_SLOT2_ROLE_MISMATCH: Slot 2 requires AUTHORIZING_OFFICIAL, got %s (%s)", pk.Role, pk.PrincipalID)
			}
			slot2Key = pk
			slot2Sig = &sigCopy
		}
	}

	if slot1Key == nil {
		return nil, errors.New("AC5_MISSING_SLOT1: missing valid Slot 1 (SERVICE_OWNER) signature")
	}
	if slot2Key == nil {
		return nil, errors.New("AC5_MISSING_SLOT2: missing valid Slot 2 (AUTHORIZING_OFFICIAL) signature")
	}
	if slot1Key.PrincipalID == slot2Key.PrincipalID {
		return nil, fmt.Errorf("AC5_SAME_PRINCIPAL_REJECTED: identical principal_id %q across Slot 1 and Slot 2", slot1Key.PrincipalID)
	}
	if strings.EqualFold(slot1Key.Email, slot2Key.Email) {
		return nil, fmt.Errorf("AC5_SAME_EMAIL_REJECTED: identical email %q across Slot 1 and Slot 2", slot1Key.Email)
	}
	if slot1Sig != nil && slot2Sig != nil && slot1Sig.KeyFingerprint != "" && slot2Sig.KeyFingerprint != "" &&
		strings.EqualFold(slot1Sig.KeyFingerprint, slot2Sig.KeyFingerprint) {
		return nil, fmt.Errorf("AC5_SAME_KEY_REJECTED: identical envelope signature key_fingerprint %q across Slot 1 and Slot 2", slot1Sig.KeyFingerprint)
	}
	if strings.EqualFold(slot1Key.KeyFingerprint, slot2Key.KeyFingerprint) ||
		SHA256Hex(slot1Key.PublicKeyBytes) == SHA256Hex(slot2Key.PublicKeyBytes) {
		return nil, fmt.Errorf("AC5_SAME_KEY_REJECTED: identical public key fingerprint %q across Slot 1 and Slot 2", slot1Key.KeyFingerprint)
	}

	return &DualHumanVerificationResult{
		CanonicalPayload: canon,
		PayloadSHA256:    SHA256Hex(canon),
		Slot1:            slot1Key,
		Slot2:            slot2Key,
	}, nil
}

// SinglePrincipalVerificationResult captures a verified 1-of-2 active human principal signature
// for fail-closed asymmetric actions (e.g. REVOKE_PRINCIPAL, EMERGENCY_FREEZE, EMERGENCY_ROLLBACK).
type SinglePrincipalVerificationResult struct {
	CanonicalPayload []byte
	PayloadSHA256    string
	Signer           *PrincipalKey
}

// VerifySingleActivePrincipalCeremony verifies a 1-of-2 DSSE envelope signed by ANY single active
// (unrevoked) SERVICE_OWNER or AUTHORIZING_OFFICIAL principal.
func VerifySingleActivePrincipalCeremony(env *Envelope, expectedPayloadType string, resolver KeyResolver, webauthnCfg WebAuthnConfig) (*SinglePrincipalVerificationResult, error) {
	if env == nil {
		return nil, errors.New("DSSE_MISSING_ENVELOPE: nil DSSE envelope")
	}
	if expectedPayloadType != "" && env.PayloadType != expectedPayloadType {
		return nil, fmt.Errorf("DSSE_PAYLOAD_TYPE_MISMATCH: got %q want %q", env.PayloadType, expectedPayloadType)
	}
	if len(env.Signatures) < 1 {
		return nil, errors.New("DSSE_SIGNATURE_REQUIRED: expected at least 1 active principal signature")
	}
	rawPayload, err := env.DecodePayload()
	if err != nil {
		return nil, fmt.Errorf("DSSE_PAYLOAD_DECODE_ERR: %w", err)
	}
	canon, err := CanonicalizeJSON(rawPayload)
	if err != nil {
		return nil, fmt.Errorf("DSSE_JCS_INVALID: %w", err)
	}
	if string(canon) != string(rawPayload) {
		return nil, errors.New("DSSE_PAYLOAD_NOT_CANONICAL_JCS: payload bytes deviate from RFC 8785 JCS")
	}

	sig := env.Signatures[0]
	pk, err := resolver.ResolveKey(sig.KeyID)
	if err != nil {
		return nil, fmt.Errorf("AC5_UNKNOWN_SIGNER: %w", err)
	}
	if pk.Role != RoleServiceOwner && pk.Role != RoleAuthorizingOfficial {
		return nil, fmt.Errorf("AC5_UNAUTHORIZED_ROLE: role %s (%s) cannot authorize governance/emergency action", pk.Role, pk.PrincipalID)
	}
	if err := VerifySingleSignature(env.PayloadType, rawPayload, sig, pk, webauthnCfg); err != nil {
		return nil, fmt.Errorf("DSSE_SIG_INVALID: %w", err)
	}
	return &SinglePrincipalVerificationResult{
		CanonicalPayload: canon,
		PayloadSHA256:    SHA256Hex(canon),
		Signer:           pk,
	}, nil
}
