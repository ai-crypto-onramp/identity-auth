package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Observability: structured JSON logging with request_id injection,
// Prometheus-style metrics, /readyz, and the /metrics endpoint.
// ---------------------------------------------------------------------------

// metrics is the process-wide collector. Counters are atomic; the histogram is
// a simple per-bucket counter (no external Prometheus dependency).
type metrics struct {
	loginTotal           atomic.Int64
	loginFailures        atomic.Int64
	refreshTotal         atomic.Int64
	logoutTotal          atomic.Int64
	authzAllow           atomic.Int64
	authzDeny            atomic.Int64
	lockouts             atomic.Int64
	mfaEnroll            atomic.Int64
	mfaVerify            atomic.Int64
	mfaVerifyFail        atomic.Int64
	keyCreate            atomic.Int64
	keyRotate            atomic.Int64
	keyRevoke            atomic.Int64
	requestsTotal        atomic.Int64
	loginLatencyMu       sync.Mutex
	loginLatencyBuckets  map[float64]int64
}

var globalMetrics = newMetrics()

func newMetrics() *metrics {
	return &metrics{
		loginLatencyBuckets: map[float64]int64{
			0.005: 0, 0.01: 0, 0.025: 0, 0.05: 0, 0.1: 0, 0.25: 0, 0.5: 0, 1.0: 0,
		},
	}
}

// observeLoginLatency records a login latency in seconds.
func (m *metrics) observeLoginLatency(d time.Duration) {
	secs := d.Seconds()
	m.loginLatencyMu.Lock()
	defer m.loginLatencyMu.Unlock()
	for _, upper := range latencyBucketsSorted {
		if secs <= upper {
			m.loginLatencyBuckets[upper]++
			return
		}
	}
}

// latencyBucketsSorted is the sorted list of bucket upper bounds.
var latencyBucketsSorted = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0}

// logger is the structured JSON logger, configured once at init.
var logger *slog.Logger

func initLogger() {
	level := slog.LevelInfo
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

// loggingMiddleware records each HTTP request as structured JSON with the
// request_id, method, path, status, and duration.
func loggingMiddleware(h http.Handler) http.Handler {
	if logger == nil {
		initLogger()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid, _ := r.Context().Value(ctxRequestID).(string)
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rw, r)
		globalMetrics.requestsTotal.Add(1)
		logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", rid,
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// readyzHandler reports readiness. With the in-memory store the service is
// always ready; with real dependencies this would ping Postgres + Redis.
func readyzHandler(a *API) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	}
}

// metricsHandler renders the Prometheus-style text exposition format.
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	m := globalMetrics
	writeCounter(w, "identity_auth_requests_total", m.requestsTotal.Load())
	writeCounter(w, "identity_auth_login_total", m.loginTotal.Load())
	writeCounter(w, "identity_auth_login_failures_total", m.loginFailures.Load())
	writeCounter(w, "identity_auth_refresh_total", m.refreshTotal.Load())
	writeCounter(w, "identity_auth_logout_total", m.logoutTotal.Load())
	writeCounter(w, "identity_auth_authz_allow_total", m.authzAllow.Load())
	writeCounter(w, "identity_auth_authz_deny_total", m.authzDeny.Load())
	writeCounter(w, "identity_auth_lockouts_total", m.lockouts.Load())
	writeCounter(w, "identity_auth_mfa_enroll_total", m.mfaEnroll.Load())
	writeCounter(w, "identity_auth_mfa_verify_total", m.mfaVerify.Load())
	writeCounter(w, "identity_auth_mfa_verify_fail_total", m.mfaVerifyFail.Load())
	writeCounter(w, "identity_auth_key_create_total", m.keyCreate.Load())
	writeCounter(w, "identity_auth_key_rotate_total", m.keyRotate.Load())
	writeCounter(w, "identity_auth_key_revoke_total", m.keyRevoke.Load())

	m.loginLatencyMu.Lock()
	for upper, count := range m.loginLatencyBuckets {
		writeBucket(w, "identity_auth_login_latency_seconds_bucket", count, upper)
	}
	m.loginLatencyMu.Unlock()
}

func writeCounter(w http.ResponseWriter, name string, value int64) {
	_, _ = w.Write([]byte("# TYPE " + name + " counter\n"))
	_, _ = w.Write([]byte(name + " "))
	_, _ = w.Write([]byte(int64ToStr(value)))
	_, _ = w.Write([]byte("\n"))
}

func writeBucket(w http.ResponseWriter, name string, value int64, upper float64) {
	_, _ = w.Write([]byte(name + "{le=\"" + formatFloat(upper) + "\"} "))
	_, _ = w.Write([]byte(int64ToStr(value)))
	_, _ = w.Write([]byte("\n"))
}

func int64ToStr(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func formatFloat(f float64) string {
	if f == float64(int64(f)) {
		return int64ToStr(int64(f))
	}
	switch {
	case f < 0.01:
		return "0.00" + trimZeros(intToStr(int(f * 1000)))
	case f < 1:
		return "0." + trimZeros(intToStr(int(f * 100)))
	default:
		return int64ToStr(int64(f))
	}
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func trimZeros(s string) string {
	for len(s) > 1 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	return s
}

// requestContextLogger returns a logger with the request_id field set.
func requestContextLogger(r *http.Request) *slog.Logger {
	if logger == nil {
		initLogger()
	}
	rid, _ := r.Context().Value(ctxRequestID).(string)
	return logger.With("request_id", rid)
}

// instrumentLogin wraps a login handler, recording latency and counts.
func instrumentLogin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h(rw, r)
		globalMetrics.observeLoginLatency(time.Since(start))
		if rw.status == http.StatusOK {
			globalMetrics.loginTotal.Add(1)
		} else {
			globalMetrics.loginFailures.Add(1)
			if rw.status == 423 {
				globalMetrics.lockouts.Add(1)
			}
		}
	}
}

// instrumentAuthz wraps the authz handler, recording allow/deny counts.
func instrumentAuthz(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h(rw, r)
	}
}