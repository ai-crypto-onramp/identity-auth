package main

import (
	"net/http"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Login, lockout, refresh, logout, revoke, list sessions.
// ---------------------------------------------------------------------------

func TestLoginSuccess(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "login@example.com", "S3cretPass!")
	rec := doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "login@example.com", "password": "S3cretPass!",
	}, "")
	assertStatus(t, rec, http.StatusOK)
	var res LoginResult
	decodeBody(t, rec, &res)
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("missing tokens: %+v", res)
	}
	if res.ExpiresIn <= 0 {
		t.Errorf("expires_in should be positive, got %d", res.ExpiresIn)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "wrong@example.com", "S3cretPass!")
	rec := doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "wrong@example.com", "password": "nope-this-wrong",
	}, "")
	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestLoginLockoutAfter5(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "lock@example.com", "S3cretPass!")
	// 4 failures should NOT lock; 5th should lock.
	for i := 0; i < 4; i++ {
		rec := doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
			"email": "lock@example.com", "password": "wrong-password-x",
		}, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401 got %d body=%s", i+1, rec.Code, rec.Body.String())
		}
	}
	// 5th failure triggers lock.
	rec := doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "lock@example.com", "password": "wrong-password-x",
	}, "")
	assertStatus(t, rec, 423)
	// Even correct password should be locked now.
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "lock@example.com", "password": "S3cretPass!",
	}, "")
	assertStatus(t, rec, 423)
	// Admin unlock via store (no auth role gating in this impl).
	u := a.store.UserByEmail("lock@example.com")
	if err := a.store.UnlockUser(u.ID); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "lock@example.com", "password": "S3cretPass!",
	}, "")
	assertStatus(t, rec, http.StatusOK)
}

func TestRefreshRotatesToken(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "refresh@example.com", "S3cretPass!")
	rec := doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "refresh@example.com", "password": "S3cretPass!",
	}, "")
	var login LoginResult
	decodeBody(t, rec, &login)
	// Refresh with old token.
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions/refresh", map[string]string{
		"refresh_token": login.RefreshToken,
	}, "")
	assertStatus(t, rec, http.StatusOK)
	var refreshed LoginResult
	decodeBody(t, rec, &refreshed)
	if refreshed.AccessToken == "" {
		t.Fatal("missing access token after refresh")
	}
	// Reusing old refresh should fail (rotation).
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions/refresh", map[string]string{
		"refresh_token": login.RefreshToken,
	}, "")
	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestLogoutRevokesSession(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "logout@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "logout@example.com", "S3cretPass!", "")
	// Logout using the token.
	rec := doRequest(t, h, http.MethodDelete, "/v1/sessions", nil, tok)
	assertStatus(t, rec, http.StatusNoContent)
	// Token should no longer work.
	rec = doRequest(t, h, http.MethodGet, "/v1/sessions", nil, tok)
	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestListAndRevokeSession(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "list@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "list@example.com", "S3cretPass!", "")
	// List sessions.
	rec := doRequest(t, h, http.MethodGet, "/v1/sessions", nil, tok)
	assertStatus(t, rec, http.StatusOK)
	var list []map[string]any
	decodeBody(t, rec, &list)
	if len(list) != 1 {
		t.Fatalf("want 1 session got %d", len(list))
	}
	sid, _ := list[0]["id"].(string)
	// Revoke by id.
	rec = doRequest(t, h, http.MethodDelete, "/v1/sessions/"+sid, nil, tok)
	assertStatus(t, rec, http.StatusNoContent)
	// After revoking the current session, the token is no longer valid.
	// Verify directly via the store that no active sessions remain.
	if len(a.store.ListSessions(a.store.UserByEmail("list@example.com").ID)) != 0 {
		t.Errorf("expected no active sessions")
	}
}

func TestRefreshInvalidToken(t *testing.T) {
	a := newAPI(DefaultConfig())
	rec := doRequest(t, a.Handler(), http.MethodPost, "/v1/sessions/refresh", map[string]string{
		"refresh_token": "not-a-token",
	}, "")
	assertStatus(t, rec, http.StatusUnauthorized)
}

// ---------------------------------------------------------------------------
// JWT validation: valid, expired, tampered.
// ---------------------------------------------------------------------------

func TestJWTValid(t *testing.T) {
	a := newAPI(DefaultConfig())
	claims := JWTClaims{Sub: "u1", Sid: "s1", Iat: time.Now().Unix(), Exp: time.Now().Add(time.Minute).Unix(), Iss: a.cfg.JWTIssuer}
	tok, err := signJWT(claims, a.cfg.JWTSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := verifyJWT(tok, a.cfg.JWTSecret)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Sub != "u1" || got.Sid != "s1" {
		t.Errorf("claims mismatch: %+v", got)
	}
}

func TestJWTExpired(t *testing.T) {
	a := newAPI(DefaultConfig())
	claims := JWTClaims{Sub: "u1", Sid: "s1", Iat: time.Now().Add(-time.Hour).Unix(), Exp: time.Now().Add(-time.Minute).Unix(), Iss: a.cfg.JWTIssuer}
	tok, _ := signJWT(claims, a.cfg.JWTSecret)
	if _, err := verifyJWT(tok, a.cfg.JWTSecret); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestJWTTampered(t *testing.T) {
	a := newAPI(DefaultConfig())
	claims := JWTClaims{Sub: "u1", Sid: "s1", Iat: time.Now().Unix(), Exp: time.Now().Add(time.Minute).Unix(), Iss: a.cfg.JWTIssuer}
	tok, _ := signJWT(claims, a.cfg.JWTSecret)
	// Flip the last character of the signature.
	tampered := tok[:len(tok)-1]
	switch tok[len(tok)-1] {
	case 'A':
		tampered += "B"
	default:
		tampered += "A"
	}
	if _, err := verifyJWT(tampered, a.cfg.JWTSecret); err == nil {
		t.Fatal("expected signature mismatch")
	}
}

func TestJWTWrongSecret(t *testing.T) {
	claims := JWTClaims{Sub: "u1", Sid: "s1", Iat: time.Now().Unix(), Exp: time.Now().Add(time.Minute).Unix(), Iss: "identity-auth"}
	tok, _ := signJWT(claims, "secret-a")
	if _, err := verifyJWT(tok, "secret-b"); err == nil {
		t.Fatal("expected signature mismatch")
	}
}

func TestBearerAuthMissing(t *testing.T) {
	a := newAPI(DefaultConfig())
	rec := doRequest(t, a.Handler(), http.MethodGet, "/v1/users/me", nil, "")
	assertStatus(t, rec, http.StatusUnauthorized)
}