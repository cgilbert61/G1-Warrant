package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// WebAuthnConfig defines the Relying Party verification parameters.
type WebAuthnConfig struct {
	RPID           string
	AllowedOrigins []string
}

// DefaultWebAuthnConfig returns the default localhost WebAuthn configuration.
func DefaultWebAuthnConfig() WebAuthnConfig {
	return WebAuthnConfig{
		RPID: "localhost",
		AllowedOrigins: []string{
			"http://localhost:8080",
			"https://localhost:8080",
			"http://127.0.0.1:8080",
		},
	}
}

// WebAuthnMetadata carries W3C AuthenticatorAssertionResponse fields inside a DSSE signature.
type WebAuthnMetadata struct {
	AuthenticatorData string `json:"authenticatorData"` // base64url
	ClientDataJSON    string `json:"clientDataJSON"`    // base64url
	CredentialID      string `json:"credentialId"`      // base64url
	RPID              string `json:"rpId"`
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// PAEWebAuthnChallenge computes the base64url-encoded SHA-256 of the DSSE PAE bytes,
// binding a W3C WebAuthn hardware assertion directly to the canonical DSSE envelope.
func PAEWebAuthnChallenge(pae []byte) string {
	sum := sha256.Sum256(pae)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// DecodeBase64Any decodes standard or URL-safe base64 with or without padding.
func DecodeBase64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.ContainsAny(s, "-_") {
		s = strings.TrimRight(s, "=")
		return base64.RawURLEncoding.DecodeString(s)
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	s = strings.TrimRight(s, "=")
	return base64.RawStdEncoding.DecodeString(s)
}

// ParseWebAuthnRegistration extracts the credential ID, algorithm, SPKI DER public key bytes,
// and SHA-256 key fingerprint from either SPKI DER or CBOR attestationObject.
func ParseWebAuthnRegistration(attestationObjB64, publicKeySPKIB64, credentialIDB64 string, cfg WebAuthnConfig) (alg string, spkiDER []byte, fingerprint string, err error) {
	if publicKeySPKIB64 != "" {
		der, decErr := DecodeBase64Any(publicKeySPKIB64)
		if decErr == nil {
			pub, parseErr := x509.ParsePKIXPublicKey(der)
			if parseErr == nil {
				switch pub.(type) {
				case *ecdsa.PublicKey:
					return AlgWebAuthnES256, der, SHA256Hex(der), nil
				case ed25519.PublicKey:
					return AlgWebAuthnEdDSA, der, SHA256Hex(der), nil
				}
			}
		}
	}
	if attestationObjB64 == "" {
		return "", nil, "", errors.New("webauthn registration missing both publicKeySpki and attestationObject")
	}
	attBytes, err := DecodeBase64Any(attestationObjB64)
	if err != nil {
		return "", nil, "", fmt.Errorf("decode attestationObject: %w", err)
	}
	val, _, err := decodeCBORItem(attBytes, 0)
	if err != nil {
		return "", nil, "", fmt.Errorf("parse attestationObject CBOR: %w", err)
	}
	attMap, ok := val.(map[any]any)
	if !ok {
		return "", nil, "", errors.New("attestationObject is not a CBOR map")
	}
	authDataRaw, ok := attMap["authData"].([]byte)
	if !ok || len(authDataRaw) < 55 {
		return "", nil, "", errors.New("invalid authData in attestationObject")
	}
	rpHash := sha256.Sum256([]byte(cfg.RPID))
	if !bytes.Equal(authDataRaw[:32], rpHash[:]) {
		return "", nil, "", errors.New("webauthn attestation rpIdHash mismatch")
	}
	flags := authDataRaw[32]
	if (flags & 0x40) == 0 {
		return "", nil, "", errors.New("webauthn attestation missing AT (attestedCredentialData) flag")
	}
	credIDLen := int(binary.BigEndian.Uint16(authDataRaw[53:55]))
	coseOffset := 55 + credIDLen
	if len(authDataRaw) <= coseOffset {
		return "", nil, "", errors.New("authData truncated before COSE_Key")
	}
	coseVal, _, err := decodeCBORItem(authDataRaw, coseOffset)
	if err != nil {
		return "", nil, "", fmt.Errorf("decode COSE_Key: %w", err)
	}
	coseMap, ok := coseVal.(map[any]any)
	if !ok {
		return "", nil, "", errors.New("COSE_Key is not a CBOR map")
	}
	kty, _ := toInt64(coseMap[int64(1)])
	switch kty {
	case 2: // EC2 (P-256 ES256)
		xBytes, okX := coseMap[int64(-2)].([]byte)
		yBytes, okY := coseMap[int64(-3)].([]byte)
		if !okX || !okY || len(xBytes) != 32 || len(yBytes) != 32 {
			return "", nil, "", errors.New("invalid P-256 coordinates in COSE_Key")
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		if !elliptic.P256().IsOnCurve(pub.X, pub.Y) {
			return "", nil, "", errors.New("P-256 point is not on curve")
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", nil, "", err
		}
		return AlgWebAuthnES256, der, SHA256Hex(der), nil
	case 1: // OKP (Ed25519 EdDSA)
		xBytes, okX := coseMap[int64(-2)].([]byte)
		if !okX || len(xBytes) != ed25519.PublicKeySize {
			return "", nil, "", errors.New("invalid Ed25519 public key in COSE_Key")
		}
		der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(xBytes))
		if err != nil {
			return "", nil, "", err
		}
		return AlgWebAuthnEdDSA, der, SHA256Hex(der), nil
	default:
		return "", nil, "", fmt.Errorf("unsupported COSE key type: %d", kty)
	}
}

// VerifyWebAuthnAssertion verifies a W3C WebAuthn assertion over a DSSE PAE challenge.
func VerifyWebAuthnAssertion(pae []byte, sigBytes []byte, meta *WebAuthnMetadata, pubKeyBytes []byte, cfg WebAuthnConfig) error {
	if meta == nil {
		return errors.New("missing webauthn metadata")
	}
	authData, err := DecodeBase64Any(meta.AuthenticatorData)
	if err != nil {
		return fmt.Errorf("decode authenticatorData: %w", err)
	}
	if len(authData) < 37 {
		return errors.New("authenticatorData shorter than 37 bytes")
	}
	clientJSON, err := DecodeBase64Any(meta.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("decode clientDataJSON: %w", err)
	}
	var cd clientData
	if err := json.Unmarshal(clientJSON, &cd); err != nil {
		return fmt.Errorf("parse clientDataJSON: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return fmt.Errorf("invalid webauthn type %q (expected webauthn.get)", cd.Type)
	}
	expectedChallenge := PAEWebAuthnChallenge(pae)
	// Normalize padding on incoming challenge
	incomingChallenge := strings.TrimRight(cd.Challenge, "=")
	if incomingChallenge != expectedChallenge {
		return fmt.Errorf("webauthn challenge mismatch: got %q want %q", incomingChallenge, expectedChallenge)
	}
	if len(cfg.AllowedOrigins) > 0 {
		originOK := false
		for _, allowed := range cfg.AllowedOrigins {
			if strings.EqualFold(strings.TrimRight(cd.Origin, "/"), strings.TrimRight(allowed, "/")) {
				originOK = true
				break
			}
		}
		if !originOK {
			return fmt.Errorf("disallowed webauthn origin %q", cd.Origin)
		}
	}
	rpID := cfg.RPID
	if rpID == "" {
		rpID = meta.RPID
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(authData[:32], rpHash[:]) {
		return fmt.Errorf("webauthn rpIdHash mismatch for rpId %q", rpID)
	}
	flags := authData[32]
	if (flags & 0x01) == 0 {
		return errors.New("webauthn User Present (UP) flag is not set")
	}

	clientDataHash := sha256.Sum256(clientJSON)
	signedBytes := make([]byte, 0, len(authData)+32)
	signedBytes = append(signedBytes, authData...)
	signedBytes = append(signedBytes, clientDataHash[:]...)

	pubAny, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		if len(pubKeyBytes) == ed25519.PublicKeySize {
			pubAny = ed25519.PublicKey(pubKeyBytes)
		} else {
			return fmt.Errorf("parse public key: %w", err)
		}
	}

	switch pub := pubAny.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(signedBytes)
		if ecdsa.VerifyASN1(pub, digest[:], sigBytes) {
			return nil
		}
		// Fallback for raw P1363 (r || s, 64 bytes) if provided
		if len(sigBytes) == 64 {
			r := new(big.Int).SetBytes(sigBytes[:32])
			s := new(big.Int).SetBytes(sigBytes[32:])
			if ecdsa.Verify(pub, digest[:], r, s) {
				return nil
			}
		}
		return errors.New("ECDSA P-256 WebAuthn assertion signature invalid")
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, signedBytes, sigBytes) {
			return errors.New("Ed25519 WebAuthn assertion signature invalid")
		}
		return nil
	default:
		return errors.New("unsupported public key algorithm for WebAuthn verification")
	}
}

// CreateWebAuthnP256Assertion generates a real W3C WebAuthn ES256 (ECDSA P-256) hardware-format
// assertion over a DSSE PAE for testing and hardware token simulation.
func CreateWebAuthnP256Assertion(priv *ecdsa.PrivateKey, credentialID string, rpID string, origin string, pae []byte) ([]byte, *WebAuthnMetadata, error) {
	rpHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 37)
	copy(authData[:32], rpHash[:])
	authData[32] = 0x05 // UP=1 (0x01) | UV=1 (0x04)
	binary.BigEndian.PutUint32(authData[33:37], 1)

	challenge := PAEWebAuthnChallenge(pae)
	cd := clientData{
		Type:      "webauthn.get",
		Challenge: challenge,
		Origin:    origin,
	}
	clientJSON, err := json.Marshal(cd)
	if err != nil {
		return nil, nil, err
	}
	clientHash := sha256.Sum256(clientJSON)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	sigDER, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, nil, err
	}
	return sigDER, &WebAuthnMetadata{
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientJSON),
		CredentialID:      credentialID,
		RPID:              rpID,
	}, nil
}

// Minimal RFC 8949 CBOR decoder sufficient for WebAuthn attestationObject and COSE_Key.
func decodeCBORItem(data []byte, offset int) (any, int, error) {
	if offset >= len(data) {
		return nil, offset, errors.New("cbor unexpected EOF")
	}
	initial := data[offset]
	major := initial >> 5
	info := initial & 0x1F
	offset++

	readUint := func(ai byte) (uint64, error) {
		switch {
		case ai < 24:
			return uint64(ai), nil
		case ai == 24:
			if offset+1 > len(data) {
				return 0, errors.New("cbor uint8 EOF")
			}
			v := uint64(data[offset])
			offset++
			return v, nil
		case ai == 25:
			if offset+2 > len(data) {
				return 0, errors.New("cbor uint16 EOF")
			}
			v := uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2
			return v, nil
		case ai == 26:
			if offset+4 > len(data) {
				return 0, errors.New("cbor uint32 EOF")
			}
			v := uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4
			return v, nil
		case ai == 27:
			if offset+8 > len(data) {
				return 0, errors.New("cbor uint64 EOF")
			}
			v := binary.BigEndian.Uint64(data[offset : offset+8])
			offset += 8
			return v, nil
		default:
			return 0, fmt.Errorf("unsupported cbor additional info %d", ai)
		}
	}

	arg, err := readUint(info)
	if err != nil {
		return nil, offset, err
	}

	switch major {
	case 0: // unsigned int
		return int64(arg), offset, nil
	case 1: // negative int (-1 - arg)
		return -1 - int64(arg), offset, nil
	case 2: // byte string
		if offset+int(arg) > len(data) {
			return nil, offset, errors.New("cbor bytes EOF")
		}
		out := append([]byte{}, data[offset:offset+int(arg)]...)
		return out, offset + int(arg), nil
	case 3: // text string
		if offset+int(arg) > len(data) {
			return nil, offset, errors.New("cbor text EOF")
		}
		out := string(data[offset : offset+int(arg)])
		return out, offset + int(arg), nil
	case 4: // array
		arr := make([]any, 0, int(arg))
		for i := 0; i < int(arg); i++ {
			elem, next, err := decodeCBORItem(data, offset)
			if err != nil {
				return nil, next, err
			}
			arr = append(arr, elem)
			offset = next
		}
		return arr, offset, nil
	case 5: // map
		m := make(map[any]any, int(arg))
		for i := 0; i < int(arg); i++ {
			k, next, err := decodeCBORItem(data, offset)
			if err != nil {
				return nil, next, err
			}
			v, next2, err := decodeCBORItem(data, next)
			if err != nil {
				return nil, next2, err
			}
			m[k] = v
			offset = next2
		}
		return m, offset, nil
	case 7: // simple / bool / null
		switch info {
		case 20:
			return false, offset, nil
		case 21:
			return true, offset, nil
		case 22:
			return nil, offset, nil
		default:
			return arg, offset, nil
		}
	default:
		return nil, offset, fmt.Errorf("unsupported cbor major type %d", major)
	}
}

func toInt64(v any) (int64, bool) {
	n, ok := v.(int64)
	return n, ok
}
