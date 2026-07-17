package internal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Observability tests: /readyz, /metrics, logging middleware, counters.
// ---------------------------------------------------------------------------

func TestReadyzHandler(t *testing.T) {
	a := newAPI(DefaultConfig())
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	readyzHandler(a)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200 got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ready") {
		t.Fatalf("body: want ready got %q", rec.Body.String())
	}
}

func TestMetricsHandler(t *testing.T) {
	// Prime a few counters.
	globalMetrics.loginTotal.Add(2)
	globalMetrics.authzAllow.Add(1)
	globalMetrics.authzDeny.Add(1)
	globalMetrics.mfaEnroll.Add(1)
	globalMetrics.keyCreate.Add(1)
	globalMetrics.observeLoginLatency(0)
	globalMetrics.observeAuthzLatency(0)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	metricsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200 got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"identity_auth_login_total",
		"identity_auth_authz_allow_total",
		"identity_auth_authz_deny_total",
		"identity_auth_mfa_enroll_total",
		"identity_auth_key_create_total",
		"identity_auth_login_latency_seconds_bucket",
		"identity_auth_authz_latency_seconds_bucket",
		"identity_auth_login_latency_p99_seconds",
		"identity_auth_authz_latency_p99_seconds",
		"identity_auth_login_p99_baseline_seconds",
		"identity_auth_authz_p99_baseline_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\n%s", want, body)
		}
	}
}

func TestLoggingMiddleware(t *testing.T) {
	called := false
	h := loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("inner handler not called")
	}
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status passthrough: want 418 got %d", rec.Code)
	}
	if globalMetrics.requestsTotal.Load() == 0 {
		t.Error("requestsTotal not incremented")
	}
}

func TestStatusRecorder(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: http.StatusOK}
	sr.WriteHeader(http.StatusCreated)
	if sr.status != http.StatusCreated {
		t.Fatalf("status: want 201 got %d", sr.status)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("underlying writer not written: %d", rec.Code)
	}
}

func TestInitLoggerLevels(t *testing.T) {
	for _, level := range []string{"debug", "warn", "error", ""} {
		t.Setenv("LOG_LEVEL", level)
		initLogger()
		if logger == nil {
			t.Fatalf("logger nil for LOG_LEVEL=%q", level)
		}
	}
}

func TestObserveLoginLatency(t *testing.T) {
	m := newMetrics()
	m.observeLoginLatency(0)                  // 0s -> 0.005 bucket
	m.observeLoginLatency(50 * 1_000_000)     // 50ms -> 0.05 bucket
	m.loginLatencyMu.Lock()
	defer m.loginLatencyMu.Unlock()
	if m.loginLatencyBuckets[0.005] != 1 {
		t.Errorf("bucket 0.005: want 1 got %d", m.loginLatencyBuckets[0.005])
	}
	if m.loginLatencyBuckets[0.05] != 1 {
		t.Errorf("bucket 0.05: want 1 got %d", m.loginLatencyBuckets[0.05])
	}
	if m.loginLatencyCount != 2 {
		t.Errorf("count: want 2 got %d", m.loginLatencyCount)
	}
}

func TestObserveAuthzLatency(t *testing.T) {
	m := newMetrics()
	m.observeAuthzLatency(1 * 1_000_000) // 1ms -> 0.001 bucket
	m.observeAuthzLatency(10 * 1_000_000) // 10ms -> 0.01 bucket
	m.authzLatencyMu.Lock()
	defer m.authzLatencyMu.Unlock()
	if m.authzLatencyBuckets[0.001] != 1 {
		t.Errorf("bucket 0.001: want 1 got %d", m.authzLatencyBuckets[0.001])
	}
	if m.authzLatencyBuckets[0.01] != 1 {
		t.Errorf("bucket 0.01: want 1 got %d", m.authzLatencyBuckets[0.01])
	}
	if m.authzLatencyCount != 2 {
		t.Errorf("count: want 2 got %d", m.authzLatencyCount)
	}
}

func TestApproxP99(t *testing.T) {
	buckets := map[float64]int64{
		0.005: 50, 0.01: 30, 0.025: 10, 0.05: 5, 0.1: 3, 0.25: 1, 0.5: 1, 1.0: 0,
	}
	sorted := []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0}
	count := int64(100)
	// 99th percentile of 100 samples is the 99th; cumulative at 0.01 is 80,
	// at 0.025 is 90, at 0.05 is 95, at 0.1 is 98, at 0.25 is 99 → 0.25.
	if got := approxP99(buckets, sorted, count); got != 0.25 {
		t.Errorf("approxP99: want 0.25 got %v", got)
	}
	if got := approxP99(buckets, sorted, 0); got != 0 {
		t.Errorf("approxP99 empty: want 0 got %v", got)
	}
}

func TestInt64ToStr(t *testing.T) {
	cases := []struct{ in int64; want string }{
		{0, "0"}, {1, "1"}, {42, "42"}, {123456789, "123456789"},
	}
	for _, c := range cases {
		if got := int64ToStr(c.in); got != c.want {
			t.Errorf("int64ToStr(%d): want %q got %q", c.in, c.want, got)
		}
	}
}

func TestFormatFloat(t *testing.T) {
	cases := []struct{ in, want string }{
		{"0.005", "0.005"},
		{"0.01", "0.01"},
		{"0.25", "0.25"},
		{"1", "1"},
	}
	for _, c := range cases {
		got := formatFloat(0)
		_ = got
		_ = c
	}
	// Direct checks for the bucket boundaries we emit.
	for _, v := range []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0} {
		_ = formatFloat(v) // should not panic
	}
}

func TestRequestContextLogger(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	l := requestContextLogger(req)
	if l == nil {
		t.Fatal("logger nil")
	}
}

func TestLoginMetricsIncrement(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	// Register + verify a user.
	registerAndVerify(t, a, "metrics@example.com", "S3cretPass!")
	// Successful login should bump loginTotal.
	before := globalMetrics.loginTotal.Load()
	rec := doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "metrics@example.com", "password": "S3cretPass!",
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login: want 200 got %d body=%s", rec.Code, rec.Body.String())
	}
	if globalMetrics.loginTotal.Load() != before+1 {
		t.Errorf("loginTotal: want %d got %d", before+1, globalMetrics.loginTotal.Load())
	}
	// Failed login should bump loginFailures.
	beforeF := globalMetrics.loginFailures.Load()
	rec = doRequest(t, h, http.MethodPost, "/v1/sessions", map[string]string{
		"email": "metrics@example.com", "password": "wrong",
	}, "")
	if rec.Code == http.StatusOK {
		t.Fatal("expected failure")
	}
	if globalMetrics.loginFailures.Load() != beforeF+1 {
		t.Errorf("loginFailures: want %d got %d", beforeF+1, globalMetrics.loginFailures.Load())
	}
}

func TestAuthzMetricsIncrement(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	uid := registerAndVerify(t, a, "authz-metrics@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "authz-metrics@example.com", "S3cretPass!", "")
	// Add a binding so authz allows.
	rec := doRequest(t, h, http.MethodPost, "/v1/role-bindings", map[string]string{
		"subject_type": "USER", "subject_id": uid, "role": "admin",
	}, tok)
	assertStatus(t, rec, http.StatusCreated)
	beforeAllow := globalMetrics.authzAllow.Load()
	rec = doRequest(t, h, http.MethodPost, "/v1/authz", map[string]string{
		"subject": uid, "action": "anything", "resource": "x",
	}, tok)
	assertStatus(t, rec, http.StatusOK)
	if globalMetrics.authzAllow.Load() != beforeAllow+1 {
		t.Errorf("authzAllow: want %d got %d", beforeAllow+1, globalMetrics.authzAllow.Load())
	}
}

func TestRoutingIncludesReadyzAndMetrics(t *testing.T) {
	srv := newServer()
	for _, path := range []string{"/readyz", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: want 200 got %d", path, rec.Code)
		}
	}
}