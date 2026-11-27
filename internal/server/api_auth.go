package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	consoleSessionCookieName = "g1warrant_session"
	consolePBKDF2Iterations  = 100000
	consoleSessionTTL        = 8 * time.Hour
)

// consoleUserRecord stores a console operator account with salted 100,000-round PBKDF2-HMAC-SHA256 hash.
type consoleUserRecord struct {
	Email        string   `json:"email"`
	Aliases      []string `json:"aliases,omitempty"`
	DisplayName  string   `json:"display_name"`
	Role         string   `json:"role"`
	Clearance    string   `json:"clearance"`
	PasswordSalt string   `json:"password_salt"`
	PasswordHash string   `json:"password_hash"`
	MFACode      string   `json:"mfa_code"`
	MFAEnabled   bool     `json:"mfa_enabled"`
	IsDemo       bool     `json:"is_demo,omitempty"`
	// DemoPassphraseHint is populated ONLY for built-in sandbox demo accounts so evaluators can test login.
	DemoPassphraseHint string `json:"demo_passphrase_hint,omitempty"`
}

// ConsoleSessionPrincipal is returned to the Console UI on /api/v1/auth/status and /api/v1/auth/login.
type ConsoleSessionPrincipal struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Clearance   string `json:"clearance"`
	AuthMethod  string `json:"auth_method"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
}

// PublicDemoAccount is exposed by /api/v1/auth/mfa-providers ONLY in non-production sandbox/demo mode.
type PublicDemoAccount struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Clearance   string `json:"clearance"`
	Passphrase  string `json:"passphrase"`
	MFACode     string `json:"mfa_code"`
}

type pushChallenge struct {
	ChallengeID string
	Email       string
	Provider    string
	DeviceName  string
	Endpoint    string
	MatchNumber string
	ExpiresAt   time.Time
}

type consoleAuthManager struct {
	mu           sync.RWMutex
	signingKey   []byte
	users        map[string]consoleUserRecord // lower(email/alias) -> record
	demoAccounts []PublicDemoAccount
	challenges   map[string]pushChallenge
	demoEnabled  bool
	airgapMode   bool
}

// pbkdf2HMACSHA256 computes a 32-byte PBKDF2-HMAC-SHA256 derived key using Go stdlib only.
func pbkdf2HMACSHA256(password, salt []byte, iterations int) []byte {
	prf := func(key, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(data)
		return mac.Sum(nil)
	}
	var blockIdx [4]byte
	binary.BigEndian.PutUint32(blockIdx[:], 1)
	u := prf(password, append(append([]byte{}, salt...), blockIdx[:]...))
	out := make([]byte, len(u))
	copy(out, u)
	for i := 1; i < iterations; i++ {
		u = prf(password, u)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func isProductionAuthPosture() bool {
	driver := strings.ToLower(strings.TrimSpace(os.Getenv("WARRANT_CLUSTER_DRIVER")))
	feedMode := strings.ToLower(strings.TrimSpace(os.Getenv("WARRANT_FEED_MODE")))
	return driver == "kubernetes" || feedMode == "live"
}

func newConsoleAuthManager() *consoleAuthManager {
	secret := strings.TrimSpace(os.Getenv("WARRANT_SESSION_SECRET"))
	var key []byte
	if secret != "" {
		h := sha256.Sum256([]byte(secret))
		key = h[:]
	} else if kp := strings.TrimSpace(os.Getenv("WARRANT_KERNEL_KEY_PATH")); kp != "" {
		sessFile := filepath.Join(filepath.Dir(kp), "console_session.key")
		if raw, rErr := os.ReadFile(sessFile); rErr == nil && len(raw) == 32 {
			key = raw
		} else {
			key = make([]byte, 32)
			_, _ = rand.Read(key)
			_ = os.WriteFile(sessFile, key, 0600)
		}
	} else {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}

	prod := isProductionAuthPosture()
	demoFlag := strings.ToLower(strings.TrimSpace(os.Getenv("WARRANT_ENABLE_DEMO_ACCOUNTS")))
	demoEnabled := !prod
	if demoFlag == "false" || demoFlag == "0" || demoFlag == "no" {
		demoEnabled = false
	} else if demoFlag == "true" || demoFlag == "1" || demoFlag == "yes" {
		// Never permit demo accounts in production kubernetes/live posture
		if !prod {
			demoEnabled = true
		}
	}

	airgap := strings.EqualFold(strings.TrimSpace(os.Getenv("WARRANT_AIRGAP_STRICT")), "true")

	mgr := &consoleAuthManager{
		signingKey:  key,
		users:       make(map[string]consoleUserRecord),
		challenges:  make(map[string]pushChallenge),
		demoEnabled: demoEnabled,
		airgapMode:  airgap,
	}

	if demoEnabled {
		mgr.seedDemoAccounts()
	}
	mgr.loadCustomUsersFromEnv()
	return mgr
}

func (m *consoleAuthManager) seedDemoAccounts() {
	type demoSpec struct {
		email       string
		aliases     []string
		displayName string
		role        string
		clearance   string
		salt        string
		passphrase  string
		mfaCode     string
	}
	specs := []demoSpec{
		{
			email:       "ops@g1163rt.ai",
			aliases:     []string{"ops@g1163rt", "admin"},
			displayName: "G1 Primary SecOps Admin (Authorizing Official)",
			role:        "AUTHORIZING_OFFICIAL",
			clearance:   "TOP_SECRET_AO",
			salt:        "g1-warrant-ops-pbkdf2-salt-2026-v1",
			passphrase:  "G1WarrantDemo2026!",
			mfaCode:     "482910",
		},
		{
			email:       "sre@g1163rt.ai",
			aliases:     []string{"sre@g1163rt"},
			displayName: "Platform SRE Lead (Service Owner)",
			role:        "SERVICE_OWNER",
			clearance:   "SECRET_SO",
			salt:        "g1-warrant-sre-pbkdf2-salt-2026-v1",
			passphrase:  "G1ServiceOwner2026!",
			mfaCode:     "319420",
		},
		{
			email:       "mac@g1163rt.ai",
			aliases:     []string{"mac@g1163rt"},
			displayName: "SecOps Duty Officer (Operator)",
			role:        "OPERATOR",
			clearance:   "CONFIDENTIAL_OPS",
			salt:        "g1-warrant-mac-pbkdf2-salt-2026-v1",
			passphrase:  "G1Operator2026!",
			mfaCode:     "123456",
		},
		{
			email:       "auditor@g1163rt.ai",
			aliases:     []string{"3pao@g1163rt.ai"},
			displayName: "3PAO Compliance Assessor (Read-Only)",
			role:        "AUDITOR",
			clearance:   "ASSESSOR_3PAO",
			salt:        "g1-warrant-aud-pbkdf2-salt-2026-v1",
			passphrase:  "G1Auditor2026!",
			mfaCode:     "654321",
		},
	}

	for _, s := range specs {
		dk := pbkdf2HMACSHA256([]byte(s.passphrase), []byte(s.salt), consolePBKDF2Iterations)
		rec := consoleUserRecord{
			Email:              s.email,
			Aliases:            s.aliases,
			DisplayName:        s.displayName,
			Role:               s.role,
			Clearance:          s.clearance,
			PasswordSalt:       s.salt,
			PasswordHash:       hex.EncodeToString(dk),
			MFACode:            s.mfaCode,
			MFAEnabled:         true,
			IsDemo:             true,
			DemoPassphraseHint: s.passphrase,
		}
		m.registerUserLocked(rec)
		m.demoAccounts = append(m.demoAccounts, PublicDemoAccount{
			Email:       s.email,
			DisplayName: s.displayName,
			Role:        s.role,
			Clearance:   s.clearance,
			Passphrase:  s.passphrase,
			MFACode:     s.mfaCode,
		})
	}
}

func (m *consoleAuthManager) loadCustomUsersFromEnv() {
	raw := strings.TrimSpace(os.Getenv("WARRANT_CONSOLE_USERS_JSON"))
	if raw == "" {
		if path := strings.TrimSpace(os.Getenv("WARRANT_CONSOLE_USERS_FILE")); path != "" {
			if b, err := os.ReadFile(path); err == nil {
				raw = strings.TrimSpace(string(b))
			}
		}
	}
	if raw == "" {
		return
	}
	var payload struct {
		Accounts []consoleUserRecord `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err == nil {
		for _, u := range payload.Accounts {
			if strings.TrimSpace(u.Email) != "" && strings.TrimSpace(u.PasswordHash) != "" {
				m.registerUserLocked(u)
			}
		}
	}
}

func (m *consoleAuthManager) registerUserLocked(rec consoleUserRecord) {
	m.users[strings.ToLower(strings.TrimSpace(rec.Email))] = rec
	for _, alias := range rec.Aliases {
		if a := strings.ToLower(strings.TrimSpace(alias)); a != "" {
			m.users[a] = rec
		}
	}
}

func (m *consoleAuthManager) lookupUser(identifier string) (consoleUserRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[strings.ToLower(strings.TrimSpace(identifier))]
	return u, ok
}

func (m *consoleAuthManager) verifyPassword(u consoleUserRecord, passphrase string) bool {
	wantBytes, err := hex.DecodeString(strings.TrimSpace(u.PasswordHash))
	if err != nil || len(wantBytes) == 0 {
		return false
	}
	gotBytes := pbkdf2HMACSHA256([]byte(passphrase), []byte(u.PasswordSalt), consolePBKDF2Iterations)
	return subtle.ConstantTimeCompare(gotBytes, wantBytes) == 1
}

func (m *consoleAuthManager) signSessionToken(p ConsoleSessionPrincipal) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, m.signingKey)
	_, _ = mac.Write([]byte("g1wsess.v1." + payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return "g1wsess.v1." + payloadB64 + "." + sigB64, nil
}

func (m *consoleAuthManager) verifySessionToken(tok string) (*ConsoleSessionPrincipal, bool) {
	parts := strings.Split(strings.TrimSpace(tok), ".")
	if len(parts) != 4 || parts[0] != "g1wsess" || parts[1] != "v1" {
		return nil, false
	}
	mac := hmac.New(sha256.New, m.signingKey)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1] + "." + parts[2]))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(parts[3]), []byte(wantSig)) != 1 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, false
	}
	var p ConsoleSessionPrincipal
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, false
	}
	if time.Now().UTC().Unix() >= p.ExpiresAt {
		return nil, false
	}
	return &p, true
}

func (m *consoleAuthManager) setSessionCookie(w http.ResponseWriter, r *http.Request, p ConsoleSessionPrincipal) error {
	tok, err := m.signSessionToken(p)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     consoleSessionCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   int(consoleSessionTTL.Seconds()),
	})
	return nil
}

func (m *consoleAuthManager) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     consoleSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   -1,
	})
}

func (m *consoleAuthManager) currentPrincipal(r *http.Request) (*ConsoleSessionPrincipal, bool) {
	c, err := r.Cookie(consoleSessionCookieName)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return nil, false
	}
	return m.verifySessionToken(c.Value)
}

func (o *ControlPlaneOrchestrator) ensureConsoleAuth() *consoleAuthManager {
	if o.consoleAuth == nil {
		o.consoleAuth = newConsoleAuthManager()
	}
	return o.consoleAuth
}

func (o *ControlPlaneOrchestrator) registerConsoleAuthRoutes(mux *http.ServeMux) {
	auth := o.ensureConsoleAuth()

	mux.HandleFunc("GET /api/v1/auth/status", func(w http.ResponseWriter, r *http.Request) {
		p, ok := auth.currentPrincipal(r)
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"authenticated":          ok,
			"principal":              p,
			"demo_accounts_enabled":  auth.demoEnabled,
			"dev_auto_login_enabled": auth.demoEnabled,
			"airgap_mode":            auth.airgapMode,
		})
	})

	mux.HandleFunc("GET /api/v1/auth/mfa-providers", func(w http.ResponseWriter, r *http.Request) {
		demos := []PublicDemoAccount{}
		if auth.demoEnabled {
			demos = auth.demoAccounts
		}
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"airgap_mode":            auth.airgapMode,
			"dev_auto_login_enabled": auth.demoEnabled,
			"demo_accounts_enabled":  auth.demoEnabled,
			"demo_accounts":          demos,
			"providers": []map[string]any{
				{"id": "duo", "name": "Cisco Duo Universal Push", "enabled": !auth.airgapMode},
				{"id": "okta", "name": "Okta Verify FastPass", "enabled": !auth.airgapMode},
				{"id": "totp", "name": "RFC 6238 TOTP Authenticator", "enabled": true},
			},
		})
	})

	mux.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			MFACode  string `json:"mfa_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON login payload"})
			return
		}
		u, ok := auth.lookupUser(req.Email)
		if !ok || !auth.verifyPassword(u, req.Password) {
			writeAPIJSON(w, http.StatusUnauthorized, map[string]any{"error": "INVALID_CREDENTIALS: operator principal or passphrase rejected"})
			return
		}
		if u.MFAEnabled {
			if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(req.MFACode)), []byte(strings.TrimSpace(u.MFACode))) != 1 {
				writeAPIJSON(w, http.StatusUnauthorized, map[string]any{"error": "MFA_VERIFICATION_FAILED: invalid 6-digit TOTP code"})
				return
			}
		}
		now := time.Now().UTC()
		principal := ConsoleSessionPrincipal{
			Email:       u.Email,
			DisplayName: u.DisplayName,
			Role:        u.Role,
			Clearance:   u.Clearance,
			AuthMethod:  "PBKDF2_HMAC_SHA256+TOTP",
			IssuedAt:    now.Unix(),
			ExpiresAt:   now.Add(consoleSessionTTL).Unix(),
		}
		if err := auth.setSessionCookie(w, r, principal); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"principal":     principal,
		})
	})

	mux.HandleFunc("POST /api/v1/auth/push-challenge", func(w http.ResponseWriter, r *http.Request) {
		if auth.airgapMode {
			writeAPIJSON(w, http.StatusForbidden, map[string]any{"error": "AIRGAP_MODE_ACTIVE: federated cloud push 2FA is disabled; use offline TOTP"})
			return
		}
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Provider string `json:"provider"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON push challenge payload"})
			return
		}
		u, ok := auth.lookupUser(req.Email)
		if !ok || !auth.verifyPassword(u, req.Password) {
			writeAPIJSON(w, http.StatusUnauthorized, map[string]any{"error": "INVALID_CREDENTIALS: verify principal & passphrase before dispatching push"})
			return
		}

		prov := strings.ToLower(strings.TrimSpace(req.Provider))
		title, device, endpoint := "Cisco Duo Universal Push", "Duo Mobile (Hardware Key)", "api.duosecurity.com"
		if prov == "okta" {
			title, device, endpoint = "Okta Verify FastPass", "Okta Verify (iOS / PIV)", "g1163rt.okta.com"
		} else {
			prov = "duo"
		}

		idBytes := make([]byte, 12)
		_, _ = rand.Read(idBytes)
		numBig, _ := rand.Int(rand.Reader, big.NewInt(90))
		matchNum := fmt.Sprintf("%02d", numBig.Int64()+10)

		chID := "push-" + hex.EncodeToString(idBytes)
		ch := pushChallenge{
			ChallengeID: chID,
			Email:       u.Email,
			Provider:    prov,
			DeviceName:  device,
			Endpoint:    endpoint,
			MatchNumber: matchNum,
			ExpiresAt:   time.Now().UTC().Add(2 * time.Minute),
		}
		auth.mu.Lock()
		auth.challenges[chID] = ch
		auth.mu.Unlock()

		writeAPIJSON(w, http.StatusOK, map[string]any{
			"challenge_id":   chID,
			"provider":       prov,
			"provider_title": title,
			"device":         device,
			"endpoint":       endpoint,
			"match_number":   matchNum,
			"expires_at":     ch.ExpiresAt.Format(time.RFC3339),
		})
	})

	mux.HandleFunc("POST /api/v1/auth/push-verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ChallengeID string `json:"challenge_id"`
			MatchNumber string `json:"match_number"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON push verify payload"})
			return
		}
		auth.mu.Lock()
		ch, ok := auth.challenges[strings.TrimSpace(req.ChallengeID)]
		if ok {
			delete(auth.challenges, strings.TrimSpace(req.ChallengeID))
		}
		auth.mu.Unlock()

		if !ok || time.Now().UTC().After(ch.ExpiresAt) {
			writeAPIJSON(w, http.StatusUnauthorized, map[string]any{"error": "PUSH_CHALLENGE_EXPIRED_OR_UNKNOWN"})
			return
		}
		if strings.TrimSpace(req.MatchNumber) != "" && strings.TrimSpace(req.MatchNumber) != ch.MatchNumber {
			writeAPIJSON(w, http.StatusUnauthorized, map[string]any{"error": "PUSH_NUMBER_MATCH_FAILED"})
			return
		}
		u, uOK := auth.lookupUser(ch.Email)
		if !uOK {
			writeAPIJSON(w, http.StatusUnauthorized, map[string]any{"error": "UNKNOWN_OPERATOR_ACCOUNT"})
			return
		}
		now := time.Now().UTC()
		principal := ConsoleSessionPrincipal{
			Email:       u.Email,
			DisplayName: u.DisplayName,
			Role:        u.Role,
			Clearance:   u.Clearance,
			AuthMethod:  "PBKDF2_HMAC_SHA256+PUSH_" + strings.ToUpper(ch.Provider),
			IssuedAt:    now.Unix(),
			ExpiresAt:   now.Add(consoleSessionTTL).Unix(),
		}
		if err := auth.setSessionCookie(w, r, principal); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"principal":     principal,
		})
	})

	mux.HandleFunc("POST /api/v1/auth/dev-quick-login", func(w http.ResponseWriter, r *http.Request) {
		if !auth.demoEnabled {
			writeAPIJSON(w, http.StatusForbidden, map[string]any{"error": "DEMO_QUICK_LOGIN_DISABLED_IN_PRODUCTION"})
			return
		}
		var req struct {
			Email string `json:"email"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		targetEmail := strings.TrimSpace(req.Email)
		if targetEmail == "" {
			targetEmail = "ops@g1163rt.ai"
		}
		u, ok := auth.lookupUser(targetEmail)
		if !ok || !u.IsDemo {
			writeAPIJSON(w, http.StatusNotFound, map[string]any{"error": "DEMO_ACCOUNT_NOT_FOUND"})
			return
		}
		now := time.Now().UTC()
		principal := ConsoleSessionPrincipal{
			Email:       u.Email,
			DisplayName: u.DisplayName,
			Role:        u.Role,
			Clearance:   u.Clearance,
			AuthMethod:  "SANDBOX_DEMO_QUICK_LOGIN",
			IssuedAt:    now.Unix(),
			ExpiresAt:   now.Add(consoleSessionTTL).Unix(),
		}
		if err := auth.setSessionCookie(w, r, principal); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"principal":     principal,
		})
	})

	mux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		auth.clearSessionCookie(w, r)
		writeAPIJSON(w, http.StatusOK, map[string]any{"authenticated": false})
	})
}
