package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

// ---------------------------------------------------------------------------
// Remaining HTTP handlers: MFA, password reset, API keys, RBAC, authz, audit,
// admin unlock, sessions-by-id dispatch.
// ---------------------------------------------------------------------------

// routeSessionsSub dispatches /v1/sessions/ subpaths (refresh handled by the
// more specific registered pattern; everything else is treated as a session
// id for DELETE revoke).
func (a *API) routeSessionsSub(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/sessions/")
	if path == "" {
		a.routeSessions(w, r)
		return
	}
	if strings.Contains(path, "/") {
		writeError(w, r, http.StatusNotFound, "not_found", "unknown path")
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	uid := currentUserID(r)
	sess, ok := a.store.SessionByID(path)
	if !ok || sess.UserID != uid {
		failOnErr(w, r, ErrSessionNotFound)
		return
	}
	if err := a.store.RevokeSession(path); err != nil {
		failOnErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// MFA handlers.
// ---------------------------------------------------------------------------

func (a *API) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	uid := currentUserID(r)
	res, ev, err := a.store.EnrollMFA(uid, a.cfg)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	globalMetrics.mfaEnroll.Add(1)
	a.store.RecordAudit(ev)
	writeJSON(w, http.StatusOK, res)
}

func (a *API) mfaVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	uid := currentUserID(r)
	var body struct {
		Code1 string `json:"code1"`
		Code2 string `json:"code2"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ev, err := a.store.VerifyMFA(uid, body.Code1, body.Code2)
	if err != nil {
		globalMetrics.mfaVerifyFail.Add(1)
		failOnErr(w, r, err)
		return
	}
	globalMetrics.mfaVerify.Add(1)
	a.store.RecordAudit(ev)
	writeJSON(w, http.StatusOK, map[string]any{"status": "confirmed"})
}

func (a *API) mfaRecovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	uid := currentUserID(r)
	codes, ev, err := a.store.GenerateRecoveryCodes(uid)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	a.store.RecordAudit(ev)
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// mfaFactorDelete handles DELETE /v1/mfa/factors/{id}.
func (a *API) mfaFactorDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/mfa/factors/")
	if id == "" {
		writeError(w, r, http.StatusNotFound, "not_found", "factor id required")
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	uid := currentUserID(r)
	ev, err := a.store.DisableFactor(uid, id)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	a.store.RecordAudit(ev)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Password reset handlers.
// ---------------------------------------------------------------------------

func (a *API) passwordResetInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	token, ev, err := a.store.PasswordResetInit(body.Email)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	a.store.RecordAudit(ev)
	writeJSON(w, http.StatusOK, map[string]any{"reset_token": token})
}

func (a *API) passwordResetConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
		MFACode     string `json:"mfa_code"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ev, err := a.store.PasswordResetConfirm(body.Token, body.NewPassword, body.MFACode)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	a.store.RecordAudit(ev)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// ---------------------------------------------------------------------------
// API key handlers.
// ---------------------------------------------------------------------------

func (a *API) routeAPIKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		a.createAPIKey(w, r)
	case http.MethodGet:
		a.listAPIKeys(w, r)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (a *API) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PartnerID   string    `json:"partner_id"`
		Scopes      []string  `json:"scopes"`
		ExpiresAt   *time.Time `json:"expires_at"`
		IPAllowlist []string  `json:"ip_allowlist"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	res, ev, err := a.store.CreateAPIKey(body.PartnerID, body.Scopes, body.IPAllowlist, body.ExpiresAt)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	globalMetrics.keyCreate.Add(1)
	a.store.RecordAudit(ev)
	writeJSON(w, http.StatusCreated, res)
}

func (a *API) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	partnerID := r.URL.Query().Get("partner_id")
	keys := a.store.ListAPIKeys(partnerID)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		entry := map[string]any{
			"id":         k.ID,
			"partner_id": k.PartnerID,
			"prefix":     k.Prefix,
			"scopes":     k.Scopes,
		}
		if len(k.IPAllowlist) > 0 {
			entry["ip_allowlist"] = k.IPAllowlist
		}
		if k.ExpiresAt != nil {
			entry["expires_at"] = k.ExpiresAt
		}
		if k.RevokedAt != nil {
			entry["revoked_at"] = k.RevokedAt
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, out)
}

// routeAPIKeyByID handles POST /v1/api-keys/{id}/rotate and DELETE /v1/api-keys/{id}.
func (a *API) routeAPIKeyByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/api-keys/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	if id == "" {
		writeError(w, r, http.StatusNotFound, "not_found", "api key id required")
		return
	}
	if len(parts) == 2 && parts[1] == "rotate" && r.Method == http.MethodPost {
		a.rotateAPIKey(w, r, id)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		a.revokeAPIKey(w, r, id)
		return
	}
	writeError(w, r, http.StatusNotFound, "not_found", "unknown path")
}

func (a *API) rotateAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	res, ev, err := a.store.RotateAPIKey(id)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	globalMetrics.keyRotate.Add(1)
	a.store.RecordAudit(ev)
	writeJSON(w, http.StatusOK, res)
}

func (a *API) revokeAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	ev, err := a.store.RevokeAPIKey(id)
	if err != nil {
		failOnErr(w, r, err)
		return
	}
	globalMetrics.keyRevoke.Add(1)
	a.store.RecordAudit(ev)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// RBAC + authz handlers.
// ---------------------------------------------------------------------------

func (a *API) listRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, ListRoles())
}

func (a *API) routeRoleBindings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			SubjectType string `json:"subject_type"`
			SubjectID   string `json:"subject_id"`
			Role        string `json:"role"`
			ScopeType   string `json:"scope_type"`
			ScopeID     string `json:"scope_id"`
		}
		if err := readJSON(r, &body); err != nil {
			writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		b, err := a.store.AddBinding(body.SubjectType, body.SubjectID, body.Role, body.ScopeType, body.ScopeID)
		if err != nil {
			failOnErr(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, b)
	case http.MethodGet:
		st := r.URL.Query().Get("subject_type")
		sid := r.URL.Query().Get("subject_id")
		writeJSON(w, http.StatusOK, a.store.ListBindings(st, sid))
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (a *API) deleteRoleBinding(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/role-bindings/")
	if id == "" {
		writeError(w, r, http.StatusNotFound, "not_found", "binding id required")
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if err := a.store.DeleteBinding(id); err != nil {
		failOnErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) authz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var body struct {
		Subject  string `json:"subject"`
		Action   string `json:"action"`
		Resource string `json:"resource"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ctx, end := startSpan(r.Context(), "handler.authz",
		attribute.String("authz.subject", body.Subject),
		attribute.String("authz.action", body.Action),
		attribute.String("authz.resource", body.Resource),
	)
	defer end(nil)
	start := time.Now()
	res, ev := a.store.Authorize(body.Subject, body.Action, body.Resource)
	globalMetrics.observeAuthzLatency(time.Since(start))
	if res.Allow {
		globalMetrics.authzAllow.Add(1)
	} else {
		globalMetrics.authzDeny.Add(1)
		end(fmt.Errorf("authz deny"))
	}
	if ev != nil {
		a.store.RecordAudit(ev)
	}
	writeJSON(w, http.StatusOK, res)
	_ = ctx
}

// ---------------------------------------------------------------------------
// Audit + admin handlers.
// ---------------------------------------------------------------------------

func (a *API) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, a.store.ListAudit())
}

func (a *API) adminUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := a.store.UnlockUser(body.UserID); err != nil {
		failOnErr(w, r, err)
		return
	}
	a.store.RecordAudit(&AuditEvent{
		Type:      "auth.admin.unlock",
		SubjectID: body.UserID,
		Metadata:  map[string]any{},
		CreatedAt: time.Now(),
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "unlocked"})
}