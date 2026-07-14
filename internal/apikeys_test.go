package internal

import (
	"net/http"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// API keys: create (full key once), list (no full key), rotate, revoke.
// ---------------------------------------------------------------------------

func TestAPIKeyCreateAndList(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "keyuser@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "keyuser@example.com", "S3cretPass!", "")
	exp := time.Now().Add(24 * time.Hour)
	rec := doRequest(t, h, http.MethodPost, "/v1/api-keys", map[string]any{
		"partner_id":  "partner-1",
		"scopes":      []string{"tx:read", "tx:create"},
		"expires_at":  exp,
		"ip_allowlist": []string{"10.0.0.0/8"},
	}, tok)
	assertStatus(t, rec, http.StatusCreated)
	var created APIKeyResult
	decodeBody(t, rec, &created)
	if created.Key == "" {
		t.Fatal("missing full key at creation")
	}
	if created.Prefix == "" {
		t.Fatal("missing prefix")
	}
	// List should NOT include the full key.
	rec = doRequest(t, h, http.MethodGet, "/v1/api-keys?partner_id=partner-1", nil, tok)
	assertStatus(t, rec, http.StatusOK)
	var list []map[string]any
	decodeBody(t, rec, &list)
	if len(list) != 1 {
		t.Fatalf("want 1 key got %d", len(list))
	}
	if _, hasKey := list[0]["key"]; hasKey {
		t.Errorf("list must not include full key material")
	}
	if list[0]["prefix"] != created.Prefix {
		t.Errorf("prefix mismatch")
	}
}

func TestAPIKeyRotateAndRevoke(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "keyrot@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "keyrot@example.com", "S3cretPass!", "")
	rec := doRequest(t, h, http.MethodPost, "/v1/api-keys", map[string]any{
		"partner_id": "partner-2", "scopes": []string{"tx:read"},
	}, tok)
	var created APIKeyResult
	decodeBody(t, rec, &created)
	oldKey := created.Key
	// Rotate.
	rec = doRequest(t, h, http.MethodPost, "/v1/api-keys/"+created.ID+"/rotate", nil, tok)
	assertStatus(t, rec, http.StatusOK)
	var rotated APIKeyResult
	decodeBody(t, rec, &rotated)
	if rotated.Key == oldKey {
		t.Fatal("rotation must produce a new key")
	}
	// Both old and new should resolve during dual-active window.
	if a.store.ResolveAPIKey(oldKey) == nil {
		t.Errorf("old key should still resolve during dual-active window")
	}
	if a.store.ResolveAPIKey(rotated.Key) == nil {
		t.Errorf("new key should resolve")
	}
	// Revoke.
	rec = doRequest(t, h, http.MethodDelete, "/v1/api-keys/"+created.ID, nil, tok)
	assertStatus(t, rec, http.StatusNoContent)
	if a.store.ResolveAPIKey(rotated.Key) != nil {
		t.Errorf("revoked new key should not resolve")
	}
	if a.store.ResolveAPIKey(oldKey) != nil {
		t.Errorf("revoked old key should not resolve")
	}
}

func TestAPIKeyRotateUnknown(t *testing.T) {
	a := newAPI(DefaultConfig())
	registerAndVerify(t, a, "keyrotbad@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "keyrotbad@example.com", "S3cretPass!", "")
	rec := doRequest(t, a.Handler(), http.MethodPost, "/v1/api-keys/bogus/rotate", nil, tok)
	assertStatus(t, rec, http.StatusNotFound)
}

func TestAPIKeyRevokeUnknown(t *testing.T) {
	a := newAPI(DefaultConfig())
	registerAndVerify(t, a, "keyrevbad@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "keyrevbad@example.com", "S3cretPass!", "")
	rec := doRequest(t, a.Handler(), http.MethodDelete, "/v1/api-keys/bogus", nil, tok)
	assertStatus(t, rec, http.StatusNotFound)
}

func TestAPIKeyCreateMissingPartner(t *testing.T) {
	a := newAPI(DefaultConfig())
	registerAndVerify(t, a, "keynopartner@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "keynopartner@example.com", "S3cretPass!", "")
	rec := doRequest(t, a.Handler(), http.MethodPost, "/v1/api-keys", map[string]any{
		"scopes": []string{"tx:read"},
	}, tok)
	assertStatus(t, rec, http.StatusBadRequest)
}