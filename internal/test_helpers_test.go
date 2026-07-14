package internal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// Shared HTTP test helpers.
// ---------------------------------------------------------------------------

func doRequest(t *testing.T, h http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		buf.Write(b)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
}

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status: want %d got %d body=%s", want, rec.Code, rec.Body.String())
	}
}

func errEnvelope(t *testing.T, rec *httptest.ResponseRecorder) errorEnvelope {
	t.Helper()
	var env errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("not error envelope: %q err=%v", rec.Body.String(), err)
	}
	return env
}

// newReqWithID builds a request with an explicit X-Request-ID header.
func newReqWithID(method, path string, body any, rid string) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf.Write(b)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if rid != "" {
		req.Header.Set("X-Request-ID", rid)
	}
	return req
}

// httptestRecorder returns a fresh response recorder.
func httptestRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

// registerAndVerify registers a user, verifies them, returns the user id.
func registerAndVerify(t *testing.T, a *API, email, pw string) string {
	t.Helper()
	rec := doRequest(t, a.Handler(), http.MethodPost, "/v1/users", map[string]string{
		"email": email, "password": pw,
	}, "")
	assertStatus(t, rec, http.StatusCreated)
	var res struct {
		ID    string `json:"id"`
		Token string `json:"verification_token"`
	}
	decodeBody(t, rec, &res)
	rec2 := doRequest(t, a.Handler(), http.MethodPost, "/v1/users/verify", map[string]string{
		"token": res.Token,
	}, "")
	assertStatus(t, rec2, http.StatusOK)
	return res.ID
}

// loginAndGetToken logs in and returns the access token.
func loginAndGetToken(t *testing.T, a *API, email, pw, mfa string) string {
	t.Helper()
	body := map[string]string{"email": email, "password": pw}
	if mfa != "" {
		body["mfa_code"] = mfa
	}
	rec := doRequest(t, a.Handler(), http.MethodPost, "/v1/sessions", body, "")
	assertStatus(t, rec, http.StatusOK)
	var res LoginResult
	decodeBody(t, rec, &res)
	return res.AccessToken
}