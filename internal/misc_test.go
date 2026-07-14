package internal

import (
	"net/http"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Password reset flow, error envelope, request_id, audit events, admin unlock.
// ---------------------------------------------------------------------------

func TestPasswordResetFlow(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "reset@example.com", "S3cretPass!")
	// Init.
	rec := doRequest(t, h, http.MethodPost, "/v1/password/reset/init", map[string]string{
		"email": "reset@example.com",
	}, "")
	assertStatus(t, rec, http.StatusOK)
	var res struct {
		Token string `json:"reset_token"`
	}
	decodeBody(t, rec, &res)
	if res.Token == "" {
		t.Fatal("missing reset token")
	}
	// Confirm with new password (no MFA enrolled).
	rec = doRequest(t, h, http.MethodPost, "/v1/password/reset/confirm", map[string]string{
		"token": res.Token, "new_password": "NewS3cretPass!",
	}, "")
	assertStatus(t, rec, http.StatusOK)
	// Old password should fail.
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "reset@example.com", "password": "S3cretPass!",
	}, "")
	assertStatus(t, rec, http.StatusUnauthorized)
	// New password should work.
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "reset@example.com", "password": "NewS3cretPass!",
	}, "")
	assertStatus(t, rec, http.StatusOK)
}

func TestPasswordResetInvalidToken(t *testing.T) {
	a := newAPI(DefaultConfig())
	rec := doRequest(t, a.Handler(), http.MethodPost, "/v1/password/reset/confirm", map[string]string{
		"token": "bogus", "new_password": "NewS3cretPass!",
	}, "")
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestPasswordResetUnknownEmail(t *testing.T) {
	a := newAPI(DefaultConfig())
	rec := doRequest(t, a.Handler(), http.MethodPost, "/v1/password/reset/init", map[string]string{
		"email": "nope@example.com",
	}, "")
	assertStatus(t, rec, http.StatusNotFound)
}

func TestPasswordResetRequiresMFA(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "resetmfa@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "resetmfa@example.com", "S3cretPass!", "")
	secret := enrollAndConfirm(t, a, tok)
	// Init reset.
	rec := doRequest(t, h, http.MethodPost, "/v1/password/reset/init", map[string]string{
		"email": "resetmfa@example.com",
	}, "")
	var res struct {
		Token string `json:"reset_token"`
	}
	decodeBody(t, rec, &res)
	// Confirm without mfa_code should be rejected.
	rec = doRequest(t, h, http.MethodPost, "/v1/password/reset/confirm", map[string]string{
		"token": res.Token, "new_password": "NewS3cretPass!",
	}, "")
	assertStatus(t, rec, http.StatusUnauthorized)
	// Need a fresh token because the previous one wasn't consumed.
	rec = doRequest(t, h, http.MethodPost, "/v1/password/reset/init", map[string]string{
		"email": "resetmfa@example.com",
	}, "")
	decodeBody(t, rec, &res)
	code, _ := totp(secret, time.Now())
	rec = doRequest(t, h, http.MethodPost, "/v1/password/reset/confirm", map[string]string{
		"token": res.Token, "new_password": "NewS3cretPass!", "mfa_code": code,
	}, "")
	assertStatus(t, rec, http.StatusOK)
}

func TestErrorEnvelopeShape(t *testing.T) {
	a := newAPI(DefaultConfig())
	rec := doRequest(t, a.Handler(), http.MethodPost, "/v1/sessions", map[string]string{
		"email": "nobody@example.com", "password": "wrong-password-x",
	}, "")
	assertStatus(t, rec, http.StatusUnauthorized)
	env := errEnvelope(t, rec)
	if env.Error.Code == "" {
		t.Errorf("missing code")
	}
	if env.Error.Message == "" {
		t.Errorf("missing message")
	}
	if env.Error.RequestID == "" {
		t.Errorf("missing request_id")
	}
}

func TestRequestIDHeader(t *testing.T) {
	a := newAPI(DefaultConfig())
	req := newReqWithID(http.MethodGet, "/healthz", nil, "my-request-id")
	rec := httptestRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-ID") != "my-request-id" {
		t.Errorf("request id not echoed: %q", rec.Header().Get("X-Request-ID"))
	}
}

func TestRequestIDGenerated(t *testing.T) {
	a := newAPI(DefaultConfig())
	req := newReqWithID(http.MethodGet, "/healthz", nil, "")
	rec := httptestRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-ID") == "" {
		t.Errorf("request id should be generated")
	}
}

func TestRequestIDPropagatedToError(t *testing.T) {
	a := newAPI(DefaultConfig())
	req := newReqWithID(http.MethodPost, "/v1/sessions", map[string]string{
		"email": "nobody@example.com", "password": "wrong-password-x",
	}, "rid-123")
	rec := httptestRecorder()
	a.Handler().ServeHTTP(rec, req)
	env := errEnvelope(t, rec)
	if env.Error.RequestID != "rid-123" {
		t.Errorf("request_id in error: want rid-123 got %q", env.Error.RequestID)
	}
}

// ---------------------------------------------------------------------------
// Audit events emitted for key actions.
// ---------------------------------------------------------------------------

func TestAuditEventsEmitted(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "auditall@example.com", "S3cretPass!")
	// login
	rec := doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "auditall@example.com", "password": "S3cretPass!",
	}, "")
	var login LoginResult
	decodeBody(t, rec, &login)
	// logout
	doRequest(t, h, http.MethodDelete, "/v1/sessions", nil, login.AccessToken)

	events := a.store.ListAudit()
	types := map[string]bool{}
	for _, ev := range events {
		types[ev.Type] = true
	}
	for _, want := range []string{"auth.login", "auth.logout", "user.register", "user.verify"} {
		if !types[want] {
			t.Errorf("missing audit event %q (have %v)", want, eventKeys(types))
		}
	}
}

func eventKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------------------
// /v1/audit-events listing.
// ---------------------------------------------------------------------------

func TestListAuditEventsEndpoint(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "auditlist@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "auditlist@example.com", "S3cretPass!", "")
	rec := doRequest(t, h, http.MethodGet, "/v1/audit-events", nil, tok)
	assertStatus(t, rec, http.StatusOK)
	var list []AuditEvent
	decodeBody(t, rec, &list)
	if len(list) == 0 {
		t.Fatalf("expected audit events")
	}
}

// ---------------------------------------------------------------------------
// Admin unlock endpoint.
// ---------------------------------------------------------------------------

func TestAdminUnlockEndpoint(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "adminunlock@example.com", "S3cretPass!")
	// A separate caller to authenticate the admin endpoint.
	registerAndVerify(t, a, "admincaller@example.com", "S3cretPass!")
	callerTok := loginAndGetToken(t, a, "admincaller@example.com", "S3cretPass!", "")
	uid := a.store.UserByEmail("adminunlock@example.com").ID
	// Force a lockout.
	for i := 0; i < 5; i++ {
		doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
			"email": "adminunlock@example.com", "password": "wrong-password-x",
		}, "")
	}
	if !a.store.isLocked(uid) {
		t.Fatal("expected locked")
	}
	// Admin unlock via the endpoint (auth as the separate caller).
	rec := doRequest(t, h, http.MethodPost, "/v1/admin/unlock", map[string]string{
		"user_id": uid,
	}, callerTok)
	if rec.Code == 423 || rec.Code == http.StatusUnauthorized {
		t.Fatalf("unlock failed: %d body=%s", rec.Code, rec.Body.String())
	}
	assertStatus(t, rec, http.StatusOK)
	if a.store.isLocked(uid) {
		t.Errorf("expected unlocked")
	}
}