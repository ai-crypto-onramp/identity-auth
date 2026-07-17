package internal

import (
	"net/http"
	"os"
	"testing"
	"time"
)

// nowForTest returns a fixed reference time for deterministic tests.
func nowForTest() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) }

// ---------------------------------------------------------------------------
// Coverage补充: config, direct store helpers, method-not-allowed, error
// envelope paths, split helpers, totp.
// ---------------------------------------------------------------------------

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("JWT_SECRET", "secret-from-env")
	t.Setenv("JWT_ISSUER", "issuer-env")
	t.Setenv("MFA_ISSUER", "mfa-env")
	t.Setenv("LOCKOUT_THRESHOLD", "7")
	t.Setenv("LOCKOUT_BASE_SECONDS", "60")
	t.Setenv("PASSWORD_MIN_LENGTH", "10")
	cfg := ConfigFromEnv()
	if cfg.JWTSecret != "secret-from-env" {
		t.Errorf("JWTSecret: %q", cfg.JWTSecret)
	}
	if cfg.JWTIssuer != "issuer-env" {
		t.Errorf("JWTIssuer: %q", cfg.JWTIssuer)
	}
	if cfg.MFAIssuer != "mfa-env" {
		t.Errorf("MFAIssuer: %q", cfg.MFAIssuer)
	}
	if cfg.LockoutThreshold != 7 {
		t.Errorf("LockoutThreshold: %d", cfg.LockoutThreshold)
	}
	if cfg.LockoutBaseSeconds != 60 {
		t.Errorf("LockoutBaseSeconds: %d", cfg.LockoutBaseSeconds)
	}
	if cfg.PasswordMinLength != 10 {
		t.Errorf("PasswordMinLength: %d", cfg.PasswordMinLength)
	}
}

func TestConfigFromEnvInvalidValues(t *testing.T) {
	t.Setenv("LOCKOUT_THRESHOLD", "not-a-number")
	t.Setenv("LOCKOUT_BASE_SECONDS", "")
	t.Setenv("PASSWORD_MIN_LENGTH", "-5")
	cfg := ConfigFromEnv()
	if cfg.LockoutThreshold != LockoutThreshold {
		t.Errorf("invalid LOCKOUT_THRESHOLD should fall back to default")
	}
	if cfg.PasswordMinLength != 8 {
		t.Errorf("invalid PASSWORD_MIN_LENGTH should fall back to default")
	}
}

func TestConfigFromEnvNoVars(t *testing.T) {
	// Clear all env vars ConfigFromEnv reads.
	for _, k := range []string{"JWT_SECRET", "JWT_ISSUER", "MFA_ISSUER", "LOCKOUT_THRESHOLD", "LOCKOUT_BASE_SECONDS", "PASSWORD_MIN_LENGTH"} {
		os.Unsetenv(k)
	}
	cfg := ConfigFromEnv()
	if cfg.JWTSecret != "dev-secret" {
		t.Errorf("default JWTSecret: %q", cfg.JWTSecret)
	}
}

func TestVerifyUserDirect(t *testing.T) {
	s := newStore()
	u, token, err := s.CreateUser("direct@example.com", "S3cretPass!")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.VerifyUser(u.ID); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if s.users[u.ID].Status != StatusActive {
		t.Errorf("status: want ACTIVE got %q", s.users[u.ID].Status)
	}
	// Verify again should fail (not pending).
	if err := s.VerifyUser(u.ID); err != ErrInvalidToken {
		t.Errorf("re-verify: want ErrInvalidToken got %v", err)
	}
	// Invalid token via VerifyUserToken.
	if _, err := s.VerifyUserToken("bogus"); err != ErrInvalidToken {
		t.Errorf("bogus token: want ErrInvalidToken got %v", err)
	}
	_ = token
}

func TestVerifyUserUnknownID(t *testing.T) {
	s := newStore()
	if err := s.VerifyUser("nope"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	cases := []struct{ method, path string }{
		{http.MethodGet, "/v1/users"},
		{http.MethodPut, "/v1/users/verify"},
		{http.MethodPut, "/v1/sessions"},
		{http.MethodGet, "/v1/sessions/refresh"},
		{http.MethodPut, "/v1/roles"},
		{http.MethodPut, "/v1/authz"},
		{http.MethodPut, "/v1/audit-events"},
		{http.MethodGet, "/v1/admin/unlock"},
	}
	registerAndVerify(t, a, "method@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "method@example.com", "S3cretPass!", "")
	for _, c := range cases {
		rec := doRequest(t, h, c.method, c.path, nil, tok)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: want 405 got %d body=%s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}

func TestRouteSessionsSubUnknownPath(t *testing.T) {
	a := newAPI(DefaultConfig())
	registerAndVerify(t, a, "sub@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "sub@example.com", "S3cretPass!", "")
	rec := doRequest(t, a.Handler(), http.MethodDelete, "/v1/sessions/abc/def", nil, tok)
	assertStatus(t, rec, http.StatusNotFound)
}

func TestRevokeSessionUnknown(t *testing.T) {
	s := newStore()
	if err := s.RevokeSession("bogus"); err != ErrSessionNotFound {
		t.Errorf("want ErrSessionNotFound got %v", err)
	}
}

func TestLogoutUnknownSession(t *testing.T) {
	s := newStore()
	if _, err := s.Logout("bogus"); err != ErrSessionNotFound {
		t.Errorf("want ErrSessionNotFound got %v", err)
	}
}

func TestSplitHelpers(t *testing.T) {
	if a, b, c := split3("a.b.c"); a != "a" || b != "b" || c != "c" {
		t.Errorf("split3 wrong: %q %q %q", a, b, c)
	}
	if a, b, c := split3("ab"); a != "" || b != "" || c != "" {
		t.Errorf("split3 two parts should be empty: %q %q %q", a, b, c)
	}
	if a, b, c := split3("a.b.c.d"); a != "" || b != "" || c != "" {
		t.Errorf("split3 four parts should be empty: %q %q %q", a, b, c)
	}
	parts := splitOn("sha256$abc$def", '$', 3)
	if len(parts) != 3 || parts[0] != "sha256" || parts[1] != "abc" || parts[2] != "def" {
		t.Errorf("splitOn wrong: %v", parts)
	}
}

func TestTOTPInvalidSecret(t *testing.T) {
	if _, err := totp("!!!not-base32!!!", nowForTest()); err == nil {
		t.Fatal("expected error for invalid secret")
	}
	if totpWindowValid("!!!not-base32!!!", "000000", nowForTest(), 1) {
		t.Fatal("expected false for invalid secret")
	}
}

func TestJWTMalformed(t *testing.T) {
	if _, err := verifyJWT("not-a-jwt", "secret"); err == nil {
		t.Fatal("expected malformed error")
	}
	if _, err := verifyJWT("a.b", "secret"); err == nil {
		t.Fatal("expected malformed error for two parts")
	}
}

func TestJWTPayloadDecodeError(t *testing.T) {
	// Manually craft a token with invalid base64 payload but valid-looking structure.
	tok := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.@@@.c2ln"
	if _, err := verifyJWT(tok, "secret"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestJWTInvalidIssuer(t *testing.T) {
	a := newAPI(DefaultConfig())
	claims := JWTClaims{Sub: "u1", Sid: "s1", Iss: "wrong-issuer", Iat: nowForTest().Unix(), Exp: nowForTest().Add(time.Minute).Unix()}
	tok, _ := signJWT(claims, a.cfg.JWTSecret)
	req := newReqWithID(http.MethodGet, "/v1/users/me", nil, "")
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptestRecorder()
	a.Handler().ServeHTTP(rec, req)
	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestPasswordResetConfirmWeakPassword(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "resetweak@example.com", "S3cretPass!")
	rec := doRequest(t, h, http.MethodPost, "/v1/password/reset/init", map[string]string{
		"email": "resetweak@example.com",
	}, "")
	var res struct {
		Token string `json:"reset_token"`
	}
	decodeBody(t, rec, &res)
	rec = doRequest(t, h, http.MethodPost, "/v1/password/reset/confirm", map[string]string{
		"token": res.Token, "new_password": "short",
	}, "")
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestPasswordResetConfirmClosedAccount(t *testing.T) {
	s := newStore()
	cfg := DefaultConfig()
	u, _, _ := s.CreateUser("resetclosed@example.com", "S3cretPass!")
	_ = s.VerifyUser(u.ID)
	// Soft-delete.
	if err := s.SoftDeleteUser(u.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, _, err := s.PasswordResetInit("resetclosed@example.com"); err != ErrAccountClosed {
		t.Errorf("want ErrAccountClosed got %v", err)
	}
	_ = cfg
}

func TestUpdateUserEmailClosed(t *testing.T) {
	s := newStore()
	u, _, _ := s.CreateUser("updclosed@example.com", "S3cretPass!")
	_ = s.VerifyUser(u.ID)
	_ = s.SoftDeleteUser(u.ID)
	if _, err := s.UpdateUserEmail(u.ID, "new@example.com"); err != ErrAccountClosed {
		t.Errorf("want ErrAccountClosed got %v", err)
	}
}

func TestSetUserPasswordUnknownUser(t *testing.T) {
	s := newStore()
	if err := s.SetUserPassword("bogus", "S3cretPass!"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestSetUserPasswordWeak(t *testing.T) {
	s := newStore()
	u, _, _ := s.CreateUser("pwweak@example.com", "S3cretPass!")
	if err := s.SetUserPassword(u.ID, "short"); err != ErrWeakPassword {
		t.Errorf("want ErrWeakPassword got %v", err)
	}
}

func TestCreateUserEmptyEmail(t *testing.T) {
	s := newStore()
	if _, _, err := s.CreateUser("", "S3cretPass!"); err != ErrBadRequest {
		t.Errorf("want ErrBadRequest got %v", err)
	}
}

func TestSoftDeleteUnknownUser(t *testing.T) {
	s := newStore()
	if err := s.SoftDeleteUser("bogus"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestUnlockUserUnknown(t *testing.T) {
	s := newStore()
	if err := s.UnlockUser("bogus"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestEnrollMFAUnknownUser(t *testing.T) {
	s := newStore()
	if _, _, err := s.EnrollMFA("bogus", DefaultConfig()); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestEnrollMFAClosedAccount(t *testing.T) {
	s := newStore()
	u, _, _ := s.CreateUser("mfaclosed@example.com", "S3cretPass!")
	_ = s.VerifyUser(u.ID)
	_ = s.SoftDeleteUser(u.ID)
	if _, _, err := s.EnrollMFA(u.ID, DefaultConfig()); err != ErrAccountClosed {
		t.Errorf("want ErrAccountClosed got %v", err)
	}
}

func TestVerifyMFANoUnconfirmedFactor(t *testing.T) {
	s := newStore()
	u, _, _ := s.CreateUser("mfano@example.com", "S3cretPass!")
	_ = s.VerifyUser(u.ID)
	if _, err := s.VerifyMFA(u.ID, "000000", "000000"); err != ErrFactorNotConfirmed {
		t.Errorf("want ErrFactorNotConfirmed got %v", err)
	}
}

func TestGenerateRecoveryCodesUnknownUser(t *testing.T) {
	s := newStore()
	if _, _, err := s.GenerateRecoveryCodes("bogus"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestCreateAPIKeyEmptyPartner(t *testing.T) {
	s := newStore()
	if _, _, err := s.CreateAPIKey("", nil, nil, nil); err != ErrBadRequest {
		t.Errorf("want ErrBadRequest got %v", err)
	}
}

func TestRotateAPIKeyUnknown(t *testing.T) {
	s := newStore()
	if _, _, err := s.RotateAPIKey("bogus"); err != ErrAPIKeyNotFound {
		t.Errorf("want ErrAPIKeyNotFound got %v", err)
	}
}

func TestRevokeAPIKeyUnknown(t *testing.T) {
	s := newStore()
	if _, err := s.RevokeAPIKey("bogus"); err != ErrAPIKeyNotFound {
		t.Errorf("want ErrAPIKeyNotFound got %v", err)
	}
}

func TestAddBindingInvalidRole(t *testing.T) {
	s := newStore()
	if _, err := s.AddBinding("USER", "x", "nope", "", ""); err != ErrBadRequest {
		t.Errorf("want ErrBadRequest got %v", err)
	}
	if _, err := s.AddBinding("USER", "", "admin", "", ""); err != ErrBadRequest {
		t.Errorf("want ErrBadRequest for empty subject got %v", err)
	}
}

func TestDeleteBindingUnknownStore(t *testing.T) {
	s := newStore()
	if err := s.DeleteBinding("bogus"); err != ErrBindingNotFound {
		t.Errorf("want ErrBindingNotFound got %v", err)
	}
}

func TestPasswordResetInitUnknownEmail(t *testing.T) {
	s := newStore()
	if _, _, err := s.PasswordResetInit("nobody@example.com"); err != ErrUserNotFound {
		t.Errorf("want ErrUserNotFound got %v", err)
	}
}

func TestResolveAPIKeyNoMatch(t *testing.T) {
	s := newStore()
	if s.ResolveAPIKey("iko_nonexistent") != nil {
		t.Errorf("expected nil for unknown key")
	}
}

func TestListRolesHasAdmin(t *testing.T) {
	roles := ListRoles()
	found := false
	for _, r := range roles {
		if r.Name == "admin" {
			found = true
		}
	}
	if !found {
		t.Fatal("admin role missing")
	}
}

func TestRolePermissionsUnknown(t *testing.T) {
	if RolePermissions("nonexistent") != nil {
		t.Errorf("expected nil for unknown role")
	}
}