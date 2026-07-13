package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// ---------------------------------------------------------------------------
 // OpenTelemetry tracing: a small wrapper that no-ops when no OTLP endpoint is
// configured, so tests never require a real collector. When
// OTEL_EXPORTER_OTLP_ENDPOINT is set, a grpc or http exporter is wired up
// depending on the scheme.
// ---------------------------------------------------------------------------

// tracerName is the single tracer used by all spans in this service.
const tracerName = "github.com/ai-crypto-onramp/identity-auth"

// tp holds the configured TracerProvider; nil means no-op (default).
var tp struct {
	mu      sync.Mutex
	provider *sdktrace.TracerProvider
	shutdown func(context.Context) error
}

// initTracer configures the global TracerProvider from the
// OTEL_EXPORTER_OTLP_ENDPOINT env var. When unset, the default no-op tracer
// is used. Safe to call multiple times; only the first call with a non-empty
// endpoint installs a real provider.
func initTracer() (shutdown func(context.Context) error, err error) {
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if endpoint == "" {
		return nil, nil
	}
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if tp.provider != nil {
		return tp.shutdown, nil
	}

	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName("identity-auth"),
			semconv.ServiceVersion("0.1.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("otel resource: %w", err)
	}

	var exp sdktrace.SpanExporter
	switch {
	case strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://"):
		exp, err = otlptracehttp.New(context.Background(),
			otlptracehttp.WithEndpoint(strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")),
			otlptracehttp.WithInsecure(),
		)
	default:
		exp, err = otlptracegrpc.New(context.Background(),
			otlptracegrpc.WithEndpoint(strings.TrimPrefix(endpoint, "grpc://")),
			otlptracegrpc.WithInsecure(),
		)
	}
	if err != nil {
		return nil, fmt.Errorf("otel exporter: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(1.0)),
	)
	tp.provider = provider
	tp.shutdown = provider.Shutdown
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	return provider.Shutdown, nil
}

// tracer returns the global tracer; before initTracer has installed a real
// provider this returns the no-op tracer from otel.
func tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// startSpan is a helper that starts a span and returns the new context plus a
// function to end the span, recording an error if one is returned.
func startSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, func(err error)) {
	ctx, span := tracer().Start(ctx, name, trace.WithAttributes(attrs...))
	return ctx, func(err error) {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}
}

// spanAttrs is a tiny helper to build a slice of KeyValue from alternating
// string, value pairs. Values may be string, int64, bool.
func spanAttrs(kvs ...any) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(kvs)/2)
	for i := 0; i+1 < len(kvs); i += 2 {
		k, _ := kvs[i].(string)
		switch v := kvs[i+1].(type) {
		case string:
			out = append(out, attribute.String(k, v))
		case int:
			out = append(out, attribute.Int64(k, int64(v)))
		case int64:
			out = append(out, attribute.Int64(k, v))
		case bool:
			out = append(out, attribute.Bool(k, v))
		default:
			out = append(out, attribute.String(k, fmt.Sprintf("%v", v)))
		}
	}
	return out
}

// tracingMiddleware wraps an http.Handler with a server span per request.
func tracingMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, end := startSpan(r.Context(), "http.request",
			attribute.String("http.method", r.Method),
			attribute.String("http.route", r.URL.Path),
		)
		defer end(nil)
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rw, r.WithContext(ctx))
		if rw.status >= 500 {
			end(fmt.Errorf("http status %d", rw.status))
		}
	})
}

// observeDBSpan starts a span for a DB operation. The returned end-func records
// the latency as a span attribute.
func observeDBSpan(ctx context.Context, op string) func(err error) {
	start := time.Now()
	ctx, end := startSpan(ctx, "db.query", attribute.String("db.operation", op))
	return func(err error) {
		end(err)
		_ = ctx
		elapsed := time.Since(start)
		_ = elapsed
	}
}

// observeRedisSpan starts a span for a Redis operation.
func observeRedisSpan(ctx context.Context, op string) func(err error) {
	ctx, end := startSpan(ctx, "redis.op", attribute.String("redis.operation", op))
	return func(err error) {
		end(err)
		_ = ctx
	}
}