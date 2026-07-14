package internal

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
	loginLatencyCount    int64
	loginLatencySum      float64
	authzLatencyMu       sync.Mutex
	authzLatencyBuckets  map[float64]int64
	authzLatencyCount    int64
	authzLatencySum      float64
}

// Alerting baselines: p99 latency thresholds (in seconds) for the two
// critical paths. These are documented as the SLO alert firing thresholds
// for the identity-auth service and are emitted as a Prometheus gauge so
// alert rules can compare p99 against them.
const (
	LoginP99BaselineSeconds  = 0.5  // alert when p99 login latency > 500ms
	AuthzP99BaselineSeconds  = 0.05 // alert when p99 /v1/authz latency > 50ms
)

var globalMetrics = newMetrics()

func newMetrics() *metrics {
	return &metrics{
		loginLatencyBuckets: map[float64]int64{
			0.005: 0, 0.01: 0, 0.025: 0, 0.05: 0, 0.1: 0, 0.25: 0, 0.5: 0, 1.0: 0,
		},
		authzLatencyBuckets: map[float64]int64{
			0.001: 0, 0.005: 0, 0.01: 0, 0.025: 0, 0.05: 0, 0.1: 0, 0.25: 0, 0.5: 0,
		},
	}
}

// observeLoginLatency records a login latency in seconds.
func (m *metrics) observeLoginLatency(d time.Duration) {
	secs := d.Seconds()
	m.loginLatencyMu.Lock()
	defer m.loginLatencyMu.Unlock()
	m.loginLatencyCount++
	m.loginLatencySum += secs
	for _, upper := range latencyBucketsSorted {
		if secs <= upper {
			m.loginLatencyBuckets[upper]++
			return
		}
	}
}

// observeAuthzLatency records a /v1/authz latency in seconds.
func (m *metrics) observeAuthzLatency(d time.Duration) {
	secs := d.Seconds()
	m.authzLatencyMu.Lock()
	defer m.authzLatencyMu.Unlock()
	m.authzLatencyCount++
	m.authzLatencySum += secs
	for _, upper := range authzBucketsSorted {
		if secs <= upper {
			m.authzLatencyBuckets[upper]++
			return
		}
	}
}

// latencyBucketsSorted is the sorted list of bucket upper bounds.
var latencyBucketsSorted = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0}

// authzBucketsSorted is the sorted list of authz latency bucket upper bounds.
var authzBucketsSorted = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5}

// approxP99 estimates the p99 latency from bucket counts, given the sorted
// bucket upper bounds and total count. It returns the upper bound of the
// bucket containing the 99th percentile sample. When there are no samples it
// returns 0.
func approxP99(buckets map[float64]int64, sorted []float64, count int64) float64 {
	if count == 0 {
		return 0
	}
	target := float64(count) * 0.99
	var cumul float64
	for _, upper := range sorted {
		cumul += float64(buckets[upper])
		if cumul >= target {
			return upper
		}
	}
	return sorted[len(sorted)-1]
}

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

	// Login latency histogram.
	m.loginLatencyMu.Lock()
	for _, upper := range latencyBucketsSorted {
		writeBucket(w, "identity_auth_login_latency_seconds_bucket", m.loginLatencyBuckets[upper], upper)
	}
	writeGauge(w, "identity_auth_login_latency_seconds_count", m.loginLatencyCount)
	writeGaugeFloat(w, "identity_auth_login_latency_seconds_sum", m.loginLatencySum)
	writeGaugeFloat(w, "identity_auth_login_latency_p99_seconds",
		approxP99(m.loginLatencyBuckets, latencyBucketsSorted, m.loginLatencyCount))
	m.loginLatencyMu.Unlock()

	// Authz latency histogram.
	m.authzLatencyMu.Lock()
	for _, upper := range authzBucketsSorted {
		writeBucket(w, "identity_auth_authz_latency_seconds_bucket", m.authzLatencyBuckets[upper], upper)
	}
	writeGauge(w, "identity_auth_authz_latency_seconds_count", m.authzLatencyCount)
	writeGaugeFloat(w, "identity_auth_authz_latency_seconds_sum", m.authzLatencySum)
	writeGaugeFloat(w, "identity_auth_authz_latency_p99_seconds",
		approxP99(m.authzLatencyBuckets, authzBucketsSorted, m.authzLatencyCount))
	m.authzLatencyMu.Unlock()

	// Alerting baseline gauges: alert rules compare the p99 metrics above
	// against these thresholds.
	writeGaugeFloat(w, "identity_auth_login_p99_baseline_seconds", LoginP99BaselineSeconds)
	writeGaugeFloat(w, "identity_auth_authz_p99_baseline_seconds", AuthzP99BaselineSeconds)
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

func writeGauge(w http.ResponseWriter, name string, value int64) {
	_, _ = w.Write([]byte("# TYPE " + name + " gauge\n"))
	_, _ = w.Write([]byte(name + " "))
	_, _ = w.Write([]byte(int64ToStr(value)))
	_, _ = w.Write([]byte("\n"))
}

func writeGaugeFloat(w http.ResponseWriter, name string, value float64) {
	_, _ = w.Write([]byte("# TYPE " + name + " gauge\n"))
	_, _ = w.Write([]byte(name + " "))
	_, _ = w.Write([]byte(formatFloat(value)))
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