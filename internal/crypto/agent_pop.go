package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	HeaderTaskDSSE = "X-Warrant-Task-DSSE"
	HeaderAgentPoP = "X-Warrant-Agent-PoP"
)

// AgentProvenancePreimage constructs the canonical signing preimage for 3-Way Builder != Commissioner SoD:
// "G1_AGENT_PROVENANCE_V1|" + agent_id + "|" + artifact_digest + "|" + public_key_b64
func AgentProvenancePreimage(agentID, artifactDigest, publicKeyB64 string) []byte {
	msg := "G1_AGENT_PROVENANCE_V1|" +
		strings.TrimSpace(agentID) + "|" +
		strings.TrimSpace(artifactDigest) + "|" +
		strings.TrimSpace(publicKeyB64)
	return []byte(msg)
}

// SignAgentBuilderProvenance signs canonical agent artifact provenance with an Ed25519 builder/publisher key.
func SignAgentBuilderProvenance(agentID, artifactDigest, publicKeyB64 string, builderPriv ed25519.PrivateKey) (string, error) {
	if len(builderPriv) != ed25519.PrivateKeySize {
		return "", errors.New("invalid Ed25519 builder private key length")
	}
	pub := builderPriv.Public().(ed25519.PublicKey)
	if IsForbiddenLegacyPublicSeedKey(pub) {
		return "", errors.New("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: builder key derives from revoked public string seed")
	}
	sig := ed25519.Sign(builderPriv, AgentProvenancePreimage(agentID, artifactDigest, publicKeyB64))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyAgentBuilderProvenance verifies builder_provenance_sig_b64 over (agent_id, artifact_digest, public_key_b64)
// against an authoritative Ed25519 builder/publisher public key.
func VerifyAgentBuilderProvenance(agentID, artifactDigest, publicKeyB64, sigB64 string, builderPub ed25519.PublicKey) error {
	if len(builderPub) != ed25519.PublicKeySize {
		return errors.New("BUILDER_KEY_INVALID: expected 32-byte Ed25519 builder public key")
	}
	if IsForbiddenLegacyPublicSeedKey(builderPub) {
		return errors.New("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: builder public key derives from revoked public string seed")
	}
	sigBytes, err := DecodeBase64Any(strings.TrimSpace(sigB64))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("BUILDER_PROVENANCE_SIG_DECODE_FAILED: expected 64-byte base64 Ed25519 signature")
	}
	if !ed25519.Verify(builderPub, AgentProvenancePreimage(agentID, artifactDigest, publicKeyB64), sigBytes) {
		return errors.New("BUILDER_PROVENANCE_SIG_INVALID: signature failed verification over (agent_id, artifact_digest, public_key_b64)")
	}
	return nil
}

// AgentPoPPreimage constructs the wire-level Holder-of-Key Proof-of-Possession signing string:
// "G1_AGENT_POP_V1|{METHOD}|{PATH}|{SHA256(BODY)}|{TASK_TOKEN_ID}|{UNIX_TS}"
func AgentPoPPreimage(method, canonicalPath, bodySHA256, taskTokenID string, unixTS int64) []byte {
	p := strings.TrimSpace(canonicalPath)
	if p == "" {
		p = "/"
	}
	msg := fmt.Sprintf(
		"G1_AGENT_POP_V1|%s|%s|%s|%s|%d",
		strings.ToUpper(strings.TrimSpace(method)),
		p,
		strings.ToLower(strings.TrimSpace(bodySHA256)),
		strings.TrimSpace(taskTokenID),
		unixTS,
	)
	return []byte(msg)
}

// BuildAgentPoPHeader signs an HTTP request with the cnf holder Ed25519 private key and returns "<unix_ts>.<base64_sig>".
func BuildAgentPoPHeader(method, canonicalPath string, body []byte, taskTokenID string, holderPriv ed25519.PrivateKey, now time.Time) (string, error) {
	if len(holderPriv) != ed25519.PrivateKeySize {
		return "", errors.New("invalid Ed25519 holder private key")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ts := now.UTC().Unix()
	bodyHash := SHA256Hex(body)
	preimage := AgentPoPPreimage(method, canonicalPath, bodyHash, taskTokenID, ts)
	sig := ed25519.Sign(holderPriv, preimage)
	return fmt.Sprintf("%d.%s", ts, base64.StdEncoding.EncodeToString(sig)), nil
}

// VerifyAgentPoPHeader validates X-Warrant-Agent-PoP ("<unix_ts>.<base64_sig>" or JSON {"ts":...,"sig":"..."})
// against the cnf Ed25519 public key, request method, path, SHA-256(body), task_token_id, and clock skew window.
func VerifyAgentPoPHeader(popHeader, method, canonicalPath string, body []byte, taskTokenID, holderPubB64 string, now time.Time, maxSkew time.Duration) error {
	raw := strings.TrimSpace(popHeader)
	if raw == "" {
		return errors.New("MISSING_AGENT_POP_HEADER: X-Warrant-Agent-PoP required")
	}
	if maxSkew <= 0 {
		maxSkew = 5 * time.Minute
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var ts int64
	var sigB64 string
	if strings.HasPrefix(raw, "{") {
		var obj struct {
			TS  int64  `json:"ts"`
			Sig string `json:"sig"`
		}
		if err := json.Unmarshal([]byte(raw), &obj); err != nil {
			return fmt.Errorf("INVALID_AGENT_POP_JSON: %w", err)
		}
		ts, sigB64 = obj.TS, obj.Sig
	} else {
		parts := strings.SplitN(raw, ".", 2)
		if len(parts) != 2 {
			return errors.New("INVALID_AGENT_POP_FORMAT: expected '<unix_ts>.<base64_sig>'")
		}
		parsedTS, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil {
			return fmt.Errorf("INVALID_AGENT_POP_TIMESTAMP: %w", err)
		}
		ts = parsedTS
		sigB64 = strings.TrimSpace(parts[1])
	}

	skew := now.UTC().Sub(time.Unix(ts, 0).UTC())
	if skew < -maxSkew || skew > maxSkew {
		return fmt.Errorf("AGENT_POP_TIMESTAMP_OUT_OF_WINDOW: skew=%s max=%s", skew, maxSkew)
	}

	pubBytes, err := DecodeBase64Any(strings.TrimSpace(holderPubB64))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("INVALID_CNF_PUBLIC_KEY: expected 32-byte Ed25519 public key")
	}
	sigBytes, err := DecodeBase64Any(sigB64)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("INVALID_AGENT_POP_SIG: expected 64-byte Ed25519 signature")
	}

	bodyHash := SHA256Hex(body)
	preimage := AgentPoPPreimage(method, canonicalPath, bodyHash, taskTokenID, ts)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), preimage, sigBytes) {
		return errors.New("AGENT_POP_SIGNATURE_MISMATCH: holder-of-key proof failed verification over method/path/body/token")
	}
	return nil
}
