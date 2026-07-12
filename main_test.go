package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// /healthz + server wiring.
// ---------------------------------------------------------------------------

func TestHealthzHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	healthzHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", got)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf(`expected body status "ok", got %q`, body["status"])
	}
}

func TestNewServerRouting(t *testing.T) {
	srv := newServer()
	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{name: "healthz", method: http.MethodGet, path: "/healthz", wantStatus: http.StatusOK},
		{name: "unknown path", method: http.MethodGet, path: "/nope", wantStatus: http.StatusNotFound},
		{name: "root path", method: http.MethodGet, path: "/", wantStatus: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("%s %s: expected status %d, got %d", tt.method, tt.path, tt.wantStatus, rec.Code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Registration & verification.
// ---------------------------------------------------------------------------

func TestRegistrationSuccess(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	rec := doRequest(t, h, http.MethodPost, "/v1/users", map[string]string{
		"email": "alice@example.com", "password": "S3cretPass!",
	}, "")
	assertStatus(t, rec, http.StatusCreated)
	var res struct {
		ID     string `json:"id"`
		Email  string `json:"email"`
		Status string `json:"status"`
		Token  string `json:"verification_token"`
	}
	decodeBody(t, rec, &res)
	if res.Email != "alice@example.com" {
		t.Errorf("email mismatch: %q", res.Email)
	}
	if res.Status != "pending" {
		t.Errorf("status: want pending got %q", res.Status)
	}
	if res.Token == "" {
		t.Errorf("missing verification token")
	}
	if res.ID == "" {
		t.Errorf("missing user id")
	}
}

func TestRegistrationDuplicateEmail(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	first := doRequest(t, h, http.MethodPost, "/v1/users", map[string]string{
		"email": "bob@example.com", "password": "S3cretPass!",
	}, "")
	assertStatus(t, first, http.StatusCreated)
	second := doRequest(t, h, http.MethodPost, "/v1/users", map[string]string{
		"email": "bob@example.com", "password": "S3cretPass!",
	}, "")
	assertStatus(t, second, http.StatusConflict)
	env := errEnvelope(t, second)
	if env.Error.Code != "email_taken" {
		t.Errorf("code: want email_taken got %q", env.Error.Code)
	}
}

func TestRegistrationWeakPassword(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	for _, pw := range []string{"short", "password", "12345678"} {
		rec := doRequest(t, h, http.MethodPost, "/v1/users", map[string]string{
			"email": "weak@example.com", "password": pw,
		}, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("password %q: want 400 got %d body=%s", pw, rec.Code, rec.Body.String())
		}
		env := errEnvelope(t, rec)
		if env.Error.Code != "weak_password" {
			t.Errorf("code: want weak_password got %q", env.Error.Code)
		}
	}
}

func TestEmailVerification(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	uid := registerAndVerify(t, a, "verify@example.com", "S3cretPass!")
	if uid == "" {
		t.Fatal("missing user id")
	}
	rec := doRequest(t, h, http.MethodGet, "/v1/users/me", nil, loginAndGetToken(t, a, "verify@example.com", "S3cretPass!", ""))
	assertStatus(t, rec, http.StatusOK)
	var me struct {
		Status string `json:"status"`
	}
	decodeBody(t, rec, &me)
	if me.Status != "active" {
		t.Errorf("status: want active got %q", me.Status)
	}
}

func TestVerifyInvalidToken(t *testing.T) {
	a := newAPI(DefaultConfig())
	rec := doRequest(t, a.Handler(), http.MethodPost, "/v1/users/verify", map[string]string{
		"token": "bogus",
	}, "")
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestProfileUpdateAndDelete(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	uid := registerAndVerify(t, a, "profile@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "profile@example.com", "S3cretPass!", "")
	_ = uid
	// Patch email.
	rec := doRequest(t, h, http.MethodPatch, "/v1/users/me", map[string]string{
		"email": "new-profile@example.com",
	}, tok)
	assertStatus(t, rec, http.StatusOK)
	// Soft-delete.
	rec = doRequest(t, h, http.MethodDelete, "/v1/users/me", nil, tok)
	assertStatus(t, rec, http.StatusNoContent)
	// Subsequent login should fail (closed).
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "new-profile@example.com", "password": "S3cretPass!",
	}, "")
	assertStatus(t, rec, http.StatusForbidden)
}

func TestProfileUpdateDuplicateEmail(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "taken@example.com", "S3cretPass!")
	registerAndVerify(t, a, "other@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "other@example.com", "S3cretPass!", "")
	rec := doRequest(t, h, http.MethodPatch, "/v1/users/me", map[string]string{
		"email": "taken@example.com",
	}, tok)
	assertStatus(t, rec, http.StatusConflict)
}