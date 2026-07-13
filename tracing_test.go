package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTracingNoopWithoutEndpoint verifies that tracingMiddleware works
// without OTEL_EXPORTER_OTLP_ENDPOINT set (no-op tracer path).
func TestTracingNoopWithoutEndpoint(t *testing.T) {
	called := false
	h := tracingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("inner handler not called under tracing middleware")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200 got %d", rec.Code)
	}
}

// TestStartSpanNoop verifies startSpan/end is safe with the no-op tracer.
func TestStartSpanNoop(t *testing.T) {
	ctx, end := startSpan(context.Background(), "test.span")
	if ctx == nil {
		t.Fatal("context nil")
	}
	end(nil)
	end(nil) // idempotent-ish double end should not panic under no-op
}

// TestObserveDBSpanNoop exercises the DB span helper.
func TestObserveDBSpanNoop(t *testing.T) {
	end := observeDBSpan(context.Background(), "users.get")
	end(nil)
}

// TestObserveRedisSpanNoop exercises the Redis span helper.
func TestObserveRedisSpanNoop(t *testing.T) {
	end := observeRedisSpan(context.Background(), "SET")
	end(nil)
}

// TestSpanAttrs covers spanAttrs type switches.
func TestSpanAttrs(t *testing.T) {
	attrs := spanAttrs("k1", "v1", "k2", 42, "k3", int64(99), "k4", true)
	if len(attrs) != 4 {
		t.Fatalf("want 4 attrs got %d", len(attrs))
	}
}

// TestInitTracerNoEndpoint verifies initTracer returns nil when unset.
func TestInitTracerNoEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := initTracer()
	if err != nil {
		t.Fatalf("initTracer: %v", err)
	}
	if shutdown != nil {
		_ = shutdown(context.Background())
		t.Fatal("expected nil shutdown when no endpoint")
	}
}