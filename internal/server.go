package internal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Run is the service entrypoint. It initializes the tracer, builds the API
// from environment-derived config, and serves HTTP on $PORT (default 8080).
func Run() {
	shutdown, err := initTracer()
	if err != nil {
		log.Printf("otel init: %v", err)
	} else if shutdown != nil {
		defer func() { _ = shutdown(context.Background()) }()
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	_ = http.ListenAndServe(":"+port, newAPI(ConfigFromEnv()).Handler())
}

// ---------------------------------------------------------------------------
// HTTP server: routes, middleware (request_id, error envelope, auth), and
// handlers for every endpoint.
// ---------------------------------------------------------------------------

type ctxKey string

const (
	ctxRequestID ctxKey = "request_id"
	ctxUserID    ctxKey = "user_id"
	ctxSessionID ctxKey = "session_id"
)

// API is the application server wiring store + config + handlers.
type API struct {
	store Store
	cfg   *Config
}

// newAPI builds an API with the given config. When DB_URL is set it opens a
// pgx pool, runs migrations, and uses the DB-backed store. In DEV_MODE=1 the
// in-memory store is allowed; in production a DB connection failure is fatal.
func newAPI(cfg *Config) *API {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	st, err := newStoreFromEnv()
	if err != nil {
		if os.Getenv("DEV_MODE") == "1" {
			logger.Error("db store init failed; using in-memory (DEV_MODE=1)", "err", err)
			st = newStore()
		} else {
			logger.Error("db store init failed; refusing to start in production mode (set DEV_MODE=1 for local dev)", "err", err)
			os.Exit(1)
		}
	}
	return &API{store: st, cfg: cfg}
}

// newStoreFromEnv selects the store backend based on DB_URL. With no DB_URL it
// returns the in-memory store; with one it opens a pool, migrates, and returns
// the DB-backed store.
func newStoreFromEnv() (Store, error) {
	dsn := dbDSN()
	if dsn == "" {
		if os.Getenv("DEV_MODE") == "1" {
			return newStore(), nil
		}
		logger.Error("DB_URL not set and DEV_MODE!=1; refusing to start in production mode")
		os.Exit(1)
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := openPool(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if _, err := migrateUp(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return newDBStore(pool)
}

// newServer builds the HTTP handler with all routes registered (legacy entry).
func newServer() http.Handler {
	return newAPI(DefaultConfig()).Handler()
}

// Handler returns an http.Handler with middleware + routes.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/readyz", readyzHandler(a))
	mux.HandleFunc("/metrics", metricsHandler)

	// v1 routes
	mux.HandleFunc("/v1/users", a.routeUsers)
	mux.HandleFunc("/v1/users/verify", a.verifyEmail)
	mux.HandleFunc("/v1/users/me", a.requireAuth(a.routeUsersMe))

	mux.HandleFunc("/v1/sessions", a.routeSessions)
	mux.HandleFunc("/v1/sessions/", a.requireAuth(a.routeSessionsSub))
	mux.HandleFunc("/v1/sessions/refresh", a.refreshSession)
	// Authenticated session sub-resources via the sub-path dispatcher:
	//   GET    /v1/sessions         (list)   -> requireAuth
	//   DELETE /v1/sessions         (logout)-> requireAuth
	//   DELETE /v1/sessions/{id}    (revoke)-> requireAuth

	mux.HandleFunc("/v1/mfa/enroll", a.requireAuth(a.mfaEnroll))
	mux.HandleFunc("/v1/mfa/verify", a.requireAuth(a.mfaVerify))
	mux.HandleFunc("/v1/mfa/recovery", a.requireAuth(a.mfaRecovery))
	mux.HandleFunc("/v1/mfa/factors/", a.requireAuth(a.mfaFactorDelete))

	mux.HandleFunc("/v1/password/reset/init", a.passwordResetInit)
	mux.HandleFunc("/v1/password/reset/confirm", a.passwordResetConfirm)

	mux.HandleFunc("/v1/api-keys", a.requireAuth(a.routeAPIKeys))
	mux.HandleFunc("/v1/api-keys/", a.routeAPIKeyByID)

	mux.HandleFunc("/v1/roles", a.listRoles)
	mux.HandleFunc("/v1/role-bindings", a.routeRoleBindings)
	mux.HandleFunc("/v1/role-bindings/", a.deleteRoleBinding)

	mux.HandleFunc("/v1/authz", a.requireAuth(a.authz))

	mux.HandleFunc("/v1/audit-events", a.requireAuth(a.listAuditEvents))

	mux.HandleFunc("/v1/admin/unlock", a.requireAuth(a.adminUnlock))

	return withMiddleware(tracingMiddleware(loggingMiddleware(mux)))
}

// withMiddleware wraps the mux with request_id + recovery middleware.
func withMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = randID()
		}
		w.Header().Set("X-Request-ID", rid)
		ctx := context.WithValue(r.Context(), ctxRequestID, rid)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// healthzHandler is the liveness probe.
func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Error envelope helpers.
// ---------------------------------------------------------------------------

type errorEnvelope struct {
	Error errorBody `json:"error"`
}
type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	rid, _ := r.Context().Value(ctxRequestID).(string)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{Error: errorBody{
		Code: code, Message: msg, RequestID: rid,
	}})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func readJSON(r *http.Request, dst any) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return errors.New("empty body")
	}
	return json.Unmarshal(body, dst)
}

// httpStatusFor maps domain errors to HTTP status codes.
func httpStatusFor(err error) (int, string) {
	switch {
	case errors.Is(err, ErrEmailTaken):
		return http.StatusConflict, "email_taken"
	case errors.Is(err, ErrWeakPassword):
		return http.StatusBadRequest, "weak_password"
	case errors.Is(err, ErrUserNotFound):
		return http.StatusNotFound, "user_not_found"
	case errors.Is(err, ErrInvalidToken):
		return http.StatusBadRequest, "invalid_token"
	case errors.Is(err, ErrInvalidCredentials):
		return http.StatusUnauthorized, "invalid_credentials"
	case errors.Is(err, ErrAccountLocked):
		return 423, "account_locked"
	case errors.Is(err, ErrAccountClosed):
		return http.StatusForbidden, "account_closed"
	case errors.Is(err, ErrAccountPending):
		return http.StatusForbidden, "account_pending"
	case errors.Is(err, ErrMFARequired):
		return http.StatusUnauthorized, "mfa_required"
	case errors.Is(err, ErrMFAInvalid):
		return http.StatusUnauthorized, "mfa_invalid"
	case errors.Is(err, ErrMFANotEnrolled):
		return http.StatusBadRequest, "mfa_not_enrolled"
	case errors.Is(err, ErrFactorNotConfirmed):
		return http.StatusBadRequest, "factor_not_confirmed"
	case errors.Is(err, ErrSessionNotFound):
		return http.StatusNotFound, "session_not_found"
	case errors.Is(err, ErrRefreshTokenInvalid):
		return http.StatusUnauthorized, "refresh_invalid"
	case errors.Is(err, ErrAPIKeyNotFound):
		return http.StatusNotFound, "api_key_not_found"
	case errors.Is(err, ErrBindingNotFound):
		return http.StatusNotFound, "binding_not_found"
	case errors.Is(err, ErrFactorNotFound):
		return http.StatusNotFound, "factor_not_found"
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, ErrBadRequest):
		return http.StatusBadRequest, "bad_request"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func failOnErr(w http.ResponseWriter, r *http.Request, err error) {
	status, code := httpStatusFor(err)
	writeError(w, r, status, code, err.Error())
}

// ---------------------------------------------------------------------------
// Auth middleware.
// ---------------------------------------------------------------------------

// requireAuth wraps a handler requiring a valid Bearer JWT.
func (a *API) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := a.bearerClaims(r)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		// Ensure session is still active.
		if sess, ok := a.store.SessionByID(claims.Sid); !ok || sess == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "session not found")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserID, claims.Sub)
		ctx = context.WithValue(ctx, ctxSessionID, claims.Sid)
		h(w, r.WithContext(ctx))
	}
}

// bearerClaims extracts and verifies the Bearer JWT.
func (a *API) bearerClaims(r *http.Request) (JWTClaims, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return JWTClaims{}, errors.New("missing bearer token")
	}
	tok := strings.TrimPrefix(auth, "Bearer ")
	claims, err := verifyJWT(tok, a.cfg.JWTSecret)
	if err != nil {
		return JWTClaims{}, err
	}
	if claims.Iss != "" && claims.Iss != a.cfg.JWTIssuer {
		return JWTClaims{}, errors.New("invalid issuer")
	}
	return claims, nil
}

// currentUserID returns the authenticated user id from context.
func currentUserID(r *http.Request) string {
	v, _ := r.Context().Value(ctxUserID).(string)
	return v
}

// ---------------------------------------------------------------------------
// Users handlers.
// ---------------------------------------------------------------------------

func (a *API) routeUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	u, token, err := a.store.CreateUser(body.Email, body.Password)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	a.store.RecordAudit(&AuditEvent{
		Type:      "user.register",
		SubjectID: u.ID,
		Metadata:  map[string]any{"email": u.Email},
		CreatedAt: time.Now(),
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":                 u.ID,
		"email":              u.Email,
		"status":             string(u.Status),
		"verification_token": token,
	})
}

func (a *API) verifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	u, err := a.store.VerifyUserToken(body.Token)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	a.store.RecordAudit(&AuditEvent{
		Type:      "user.verify",
		SubjectID: u.ID,
		Metadata:  map[string]any{},
		CreatedAt: time.Now(),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"id":     u.ID,
		"email":  u.Email,
		"status": string(u.Status),
	})
}

func (a *API) routeUsersMe(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	if uid == "" {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "auth required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		u := a.store.UserByID(uid)
		if u == nil {
			failOnErr(w, r, ErrUserNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id":        u.ID,
			"email":     u.Email,
			"status":    string(u.Status),
			"created_at": u.CreatedAt,
		})
	case http.MethodPatch:
		var body struct {
			Email string `json:"email"`
		}
		if err := readJSON(r, &body); err != nil {
			writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		u, err := a.store.UpdateUserEmail(uid, body.Email)
		if err != nil {
			failOnErr(w, r, err)
			return
		}
		a.store.RecordAudit(&AuditEvent{
			Type:      "user.update",
			SubjectID: u.ID,
			Metadata:  map[string]any{"email": u.Email},
			CreatedAt: time.Now(),
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"id":     u.ID,
			"email":  u.Email,
			"status": string(u.Status),
		})
	case http.MethodDelete:
		if err := a.store.SoftDeleteUser(uid); err != nil {
			failOnErr(w, r, err)
			return
		}
		a.store.RecordAudit(&AuditEvent{
			Type:      "user.close",
			SubjectID: uid,
			Metadata:  map[string]any{},
			CreatedAt: time.Now(),
		})
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

// ---------------------------------------------------------------------------
// Sessions handlers.
// ---------------------------------------------------------------------------

func (a *API) routeSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		a.login(w, r)
	case http.MethodGet:
		a.requireAuth(a.listSessions)(w, r)
	case http.MethodDelete:
		a.requireAuth(a.logout)(w, r)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	ctx, end := startSpan(r.Context(), "handler.login")
	defer end(nil)
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		MFACode  string `json:"mfa_code"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	res, ev, err := a.store.Login(body.Email, body.Password, body.MFACode, a.cfg)
	if err != nil {
		if errors.Is(err, ErrAccountLocked) {
			globalMetrics.lockouts.Add(1)
			a.store.RecordAudit(&AuditEvent{
				Type: "auth.lockout", SubjectID: a.store.UserByEmail(body.Email).ID,
				Metadata: map[string]any{}, CreatedAt: time.Now(),
			})
		} else {
			globalMetrics.loginFailures.Add(1)
		}
		end(err)
		failOnErr(w, r, err)
		return
	}
	globalMetrics.loginTotal.Add(1)
	a.store.RecordAudit(ev)
	writeJSON(w, http.StatusOK, res)
	_ = ctx
}

func (a *API) refreshSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	res, ev, err := a.store.Refresh(body.RefreshToken, a.cfg)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	globalMetrics.refreshTotal.Add(1)
	a.store.RecordAudit(ev)
	writeJSON(w, http.StatusOK, res)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	sid, _ := r.Context().Value(ctxSessionID).(string)
	ev, err := a.store.Logout(sid)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	globalMetrics.logoutTotal.Add(1)
	a.store.RecordAudit(ev)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listSessions(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	sessions := a.store.ListSessions(uid)
	out := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, map[string]any{
			"id":           s.ID,
			"issued_at":    s.IssuedAt,
			"last_seen_at": s.LastSeenAt,
			"expires_at":   s.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}