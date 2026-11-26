package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConsoleAuth_LoginMFAQuickLoginPushAndLogout(t *testing.T) {
	t.Setenv("WARRANT_CLUSTER_DRIVER", "simulator")
	t.Setenv("WARRANT_FEED_MODE", "offline")

	orch := &ControlPlaneOrchestrator{}
	mux := http.NewServeMux()
	orch.registerConsoleAuthRoutes(mux)

	// 1. Unauthenticated status
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on status, got %d", rec.Code)
	}
	var st map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if st["authenticated"] != false || st["demo_accounts_enabled"] != true {
		t.Fatalf("unexpected initial status: %+v", st)
	}

	// 2. Reject invalid MFA code
	rec = httptest.NewRecorder()
	body := `{"email":"ops@g1163rt.ai","password":"G1WarrantDemo2026!","mfa_code":"000000"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on bad MFA code, got %d", rec.Code)
	}

	// 3. Valid PBKDF2 + TOTP login issues HttpOnly SameSite=Strict cookie
	rec = httptest.NewRecorder()
	body = `{"email":"ops@g1163rt.ai","password":"G1WarrantDemo2026!","mfa_code":"482910"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on valid login, got %d: %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != consoleSessionCookieName || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected HttpOnly SameSite=Strict session cookie, got %+v", cookies)
	}

	// 4. Authenticated status with cookie
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/status", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if st["authenticated"] != true {
		t.Fatalf("expected authenticated=true with valid cookie, got %+v", st)
	}

	// 5. Push 2FA challenge + verify
	rec = httptest.NewRecorder()
	body = `{"email":"sre@g1163rt.ai","password":"G1ServiceOwner2026!","provider":"okta"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/push-challenge", bytes.NewBufferString(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on push-challenge, got %d: %s", rec.Code, rec.Body.String())
	}
	var ch map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &ch)
	verifyBody, _ := json.Marshal(map[string]string{
		"challenge_id": ch["challenge_id"],
		"match_number": ch["match_number"],
	})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/push-verify", bytes.NewReader(verifyBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on push-verify, got %d: %s", rec.Code, rec.Body.String())
	}

	// 6. Demo quick-login works in simulator mode
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/dev-quick-login", bytes.NewBufferString(`{"email":"mac@g1163rt.ai"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on dev-quick-login in sandbox mode, got %d", rec.Code)
	}

	// 7. Logout clears cookie
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on logout, got %d", rec.Code)
	}
}

func TestConsoleAuth_DisablesDemoAccountsInKubernetesProductionMode(t *testing.T) {
	t.Setenv("WARRANT_CLUSTER_DRIVER", "kubernetes")
	t.Setenv("WARRANT_ENABLE_DEMO_ACCOUNTS", "true")

	orch := &ControlPlaneOrchestrator{}
	mux := http.NewServeMux()
	orch.registerConsoleAuthRoutes(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/dev-quick-login", bytes.NewBufferString(`{}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on dev-quick-login in kubernetes mode, got %d", rec.Code)
	}
}
