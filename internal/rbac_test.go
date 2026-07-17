package internal

import (
	"net/http"
	"testing"
)

// ---------------------------------------------------------------------------
// RBAC: roles list, bindings CRUD, authz allow/deny.
// ---------------------------------------------------------------------------

func TestListRoles(t *testing.T) {
	a := newAPI(DefaultConfig())
	rec := doRequest(t, a.Handler(), http.MethodGet, "/v1/roles", nil, "")
	assertStatus(t, rec, http.StatusOK)
	var roles []RoleInfo
	decodeBody(t, rec, &roles)
	want := map[string]bool{
		"user": true, "partner_admin": true, "partner_api": true,
		"support": true, "compliance": true, "ops": true, "admin": true,
	}
	if len(roles) != len(want) {
		t.Fatalf("want %d roles got %d", len(want), len(roles))
	}
	for _, r := range roles {
		if !want[r.Name] {
			t.Errorf("unexpected role %q", r.Name)
		}
		if len(r.Permissions) == 0 {
			t.Errorf("role %q has no permissions", r.Name)
		}
	}
}

func TestRoleBindingsCRUD(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "rbac@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "rbac@example.com", "S3cretPass!", "")
	uid := a.store.UserByEmail("rbac@example.com").ID
	// Create binding.
	rec := doRequest(t, h, http.MethodPost, "/v1/role-bindings", map[string]string{
		"subject_type": "USER", "subject_id": uid, "role": "partner_admin",
		"scope_type": "partner", "scope_id": "partner-1",
	}, tok)
	assertStatus(t, rec, http.StatusCreated)
	var binding RoleBinding
	decodeBody(t, rec, &binding)
	if binding.Role != "partner_admin" {
		t.Errorf("role mismatch: %q", binding.Role)
	}
	// List bindings.
	rec = doRequest(t, h, http.MethodGet, "/v1/role-bindings?subject_type=USER&subject_id="+uid, nil, tok)
	assertStatus(t, rec, http.StatusOK)
	var list []*RoleBinding
	decodeBody(t, rec, &list)
	if len(list) != 1 {
		t.Fatalf("want 1 binding got %d", len(list))
	}
	// Delete binding.
	rec = doRequest(t, h, http.MethodDelete, "/v1/role-bindings/"+binding.ID, nil, tok)
	assertStatus(t, rec, http.StatusNoContent)
	// List should now be empty.
	rec = doRequest(t, h, http.MethodGet, "/v1/role-bindings?subject_id="+uid, nil, tok)
	decodeBody(t, rec, &list)
	if len(list) != 0 {
		t.Errorf("want 0 bindings got %d", len(list))
	}
}

func TestRoleBindingInvalidRole(t *testing.T) {
	a := newAPI(DefaultConfig())
	registerAndVerify(t, a, "rbacbad@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "rbacbad@example.com", "S3cretPass!", "")
	rec := doRequest(t, a.Handler(), http.MethodPost, "/v1/role-bindings", map[string]string{
		"subject_id": "x", "role": "nonexistent_role",
	}, tok)
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestDeleteBindingUnknown(t *testing.T) {
	a := newAPI(DefaultConfig())
	registerAndVerify(t, a, "rbacdel@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "rbacdel@example.com", "S3cretPass!", "")
	rec := doRequest(t, a.Handler(), http.MethodDelete, "/v1/role-bindings/bogus", nil, tok)
	assertStatus(t, rec, http.StatusNotFound)
}

func TestAuthzAllowAndDeny(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "authz@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "authz@example.com", "S3cretPass!", "")
	uid := a.store.UserByEmail("authz@example.com").ID
	// No bindings yet → deny.
	rec := doRequest(t, h, http.MethodPost, "/v1/authz", map[string]string{
		"subject": uid, "action": "keys:create", "resource": "partner-1",
	}, tok)
	assertStatus(t, rec, http.StatusOK)
	var res AuthzResult
	decodeBody(t, rec, &res)
	if res.Allow {
		t.Errorf("expected deny with no bindings")
	}
	if len(res.Reason) == 0 {
		t.Errorf("expected reason entries")
	}
	// Grant partner_admin → keys:create allowed.
	_, err := a.store.AddBinding("USER", uid, "partner_admin", "partner", "partner-1")
	if err != nil {
		t.Fatalf("add binding: %v", err)
	}
	rec = doRequest(t, h, http.MethodPost, "/v1/authz", map[string]string{
		"subject": uid, "action": "keys:create", "resource": "partner-1",
	}, tok)
	decodeBody(t, rec, &res)
	if !res.Allow {
		t.Errorf("expected allow with partner_admin binding")
	}
}

func TestAuthzAdminWildcard(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "admin@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "admin@example.com", "S3cretPass!", "")
	uid := a.store.UserByEmail("admin@example.com").ID
	_, _ = a.store.AddBinding("USER", uid, "admin", "", "")
	rec := doRequest(t, h, http.MethodPost, "/v1/authz", map[string]string{
		"subject": uid, "action": "anything", "resource": "any",
	}, tok)
	var res AuthzResult
	decodeBody(t, rec, &res)
	if !res.Allow {
		t.Errorf("admin role should allow any action")
	}
}

func TestAuditEmittedOnAuthzDeny(t *testing.T) {
	a := newAPI(DefaultConfig())
	h := a.Handler()
	registerAndVerify(t, a, "audit@example.com", "S3cretPass!")
	tok := loginAndGetToken(t, a, "audit@example.com", "S3cretPass!", "")
	uid := a.store.UserByEmail("audit@example.com").ID
	before := len(a.store.ListAudit())
	doRequest(t, h, http.MethodPost, "/v1/authz", map[string]string{
		"subject": uid, "action": "keys:create", "resource": "x",
	}, tok)
	after := len(a.store.ListAudit())
	if after <= before {
		t.Errorf("expected audit event on deny, before=%d after=%d", before, after)
	}
	// Find the deny event.
	found := false
	for _, ev := range a.store.ListAudit() {
		if ev.Type == "auth.authz.deny" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("auth.authz.deny event not in audit log")
	}
}