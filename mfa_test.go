package main

import (
	"net/http"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// MFA: enroll, verify (wrong/correct codes), login with MFA, recovery codes,
// factor disable.
// ---------------------------------------------------------------------------

// enrollAndConfirm enrolls an MFA factor and confirms it via two consecutive
// OTPs, returning the secret for further use.
func enrollAndConfirm(t *testing.T, a *API, tok string) string {
	t.Helper()
	rec := doRequest(t, a.Handler(), http.MethodPost, "/v1/mfa/enroll", nil, tok)
	assertStatus(t, rec, http.StatusOK)
	var res MFAEnrollResult
	decodeBody(t, rec, &res)
	// Compute two consecutive valid codes (current and next step).
	now := time.Now()
	code1, _ := totp(res.Secret, now)
	code2, _ := totp(res.Secret, now.Add(30*time.Second))
	rec = doRequest(t, a.Handler(), http.MethodPost, "/v1/mfa/verify", map[string]string{
		"code1": code1, "code2": code2,
	}, tok)
	assertStatus(t, rec, http.StatusOK)
	return res.Secret
}

func TestMFAEnrollAndVerify(t *testing.T) {
	a := newAPI(DefaultConfig())
	registerAndVerify(t, a, "mfa@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "mfa@example.com", "S3cretPass!", "")
	secret := enrollAndConfirm(t, a, tok)
	if secret == "" {
		t.Fatal("missing secret")
	}
}

func TestMFAVerifyWrongCodes(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "mfabad@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "mfabad@example.com", "S3cretPass!", "")
	rec := doRequest(t, h, http.MethodPost, "/v1/mfa/enroll", nil, tok)
	assertStatus(t, rec, http.StatusOK)
	var res MFAEnrollResult
	decodeBody(t, rec, &res)
	rec = doRequest(t, h, http.MethodPost, "/v1/mfa/verify", map[string]string{
		"code1": "000000", "code2": "000000",
	}, tok)
	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestMFALoginRequiresCode(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "mfalogin@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "mfalogin@example.com", "S3cretPass!", "")
	secret := enrollAndConfirm(t, a, tok)
	// Now login should require mfa_code.
	rec := doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "mfalogin@example.com", "password": "S3cretPass!",
	}, "")
	assertStatus(t, rec, http.StatusUnauthorized)
	env := errEnvelope(t, rec)
	if env.Error.Code != "mfa_required" {
		t.Errorf("code: want mfa_required got %q", env.Error.Code)
	}
	// Login with correct code.
	code, _ := totp(secret, time.Now())
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "mfalogin@example.com", "password": "S3cretPass!", "mfa_code": code,
	}, "")
	assertStatus(t, rec, http.StatusOK)
}

func TestMFALoginInvalidCode(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "mfabad2@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "mfabad2@example.com", "S3cretPass!", "")
	enrollAndConfirm(t, a, tok)
	rec := doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "mfabad2@example.com", "password": "S3cretPass!", "mfa_code": "000000",
	}, "")
	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestMFARecoveryCodes(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "recover@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "recover@example.com", "S3cretPass!", "")
	enrollAndConfirm(t, a, tok)
	rec := doRequest(t, h, http.MethodPost, "/v1/mfa/recovery", nil, tok)
	assertStatus(t, rec, http.StatusOK)
	var res struct {
		Codes []string `json:"recovery_codes"`
	}
	decodeBody(t, rec, &res)
	if len(res.Codes) != 10 {
		t.Fatalf("want 10 recovery codes got %d", len(res.Codes))
	}
	// Use one recovery code to log in.
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "recover@example.com", "password": "S3cretPass!", "mfa_code": res.Codes[0],
	}, "")
	assertStatus(t, rec, http.StatusOK)
	// The same recovery code should not be reusable.
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "recover@example.com", "password": "S3cretPass!", "mfa_code": res.Codes[0],
	}, "")
	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestMFADisableFactor(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "mfadisable@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "mfadisable@example.com", "S3cretPass!", "")
	rec := doRequest(t, h, http.MethodPost, "/v1/mfa/enroll", nil, tok)
	var res MFAEnrollResult
	decodeBody(t, rec, &res)
	now := time.Now()
	code1, _ := totp(res.Secret, now)
	code2, _ := totp(res.Secret, now.Add(30*time.Second))
	doRequest(t, h, http.MethodPost, "/v1/mfa/verify", map[string]string{
		"code1": code1, "code2": code2,
	}, tok)
	// Disable.
	rec = doRequest(t, h, http.MethodDelete, "/v1/mfa/factors/"+res.FactorID, nil, tok)
	assertStatus(t, rec, http.StatusNoContent)
	// Login should no longer require MFA.
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "mfadisable@example.com", "password": "S3cretPass!",
	}, "")
	assertStatus(t, rec, http.StatusOK)
}

func TestMFADisableUnknownFactor(t *testing.T) {
	a := newAPI(DefaultConfig())
	registerAndVerify(t, a, "mfaunk@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "mfaunk@example.com", "S3cretPass!", "")
	rec := doRequest(t, a.Handler(), http.MethodDelete, "/v1/mfa/factors/bogus", nil, tok)
	assertStatus(t, rec, http.StatusNotFound)
}