package main

import (
	"context"
	"sort"
	"time"
)

// ---------------------------------------------------------------------------
// RBAC: fixed role/permission model, role bindings, authz decision endpoint.
// ---------------------------------------------------------------------------

// Role name constants.
const (
	RoleUser         = "user"
	RolePartnerAdmin = "partner_admin"
	RolePartnerAPI   = "partner_api"
	RoleSupport      = "support"
	RoleCompliance   = "compliance"
	RoleOps          = "ops"
	RoleAdmin        = "admin"
)

// rolePermissions maps each role to its allowed permissions.
var rolePermissions = map[string][]string{
	RoleUser:         {"profile:read", "profile:write", "session:create", "session:read", "session:delete"},
	RolePartnerAdmin: {"keys:create", "keys:read", "keys:rotate", "keys:revoke", "partner:read", "partner:write"},
	RolePartnerAPI:   {"keys:read", "partner:read"},
	RoleSupport:      {"users:read", "session:read"},
	RoleCompliance:   {"users:read", "audit:read"},
	RoleOps:          {"users:unlock", "session:read", "audit:read"},
	RoleAdmin:        {"*"},
}

// RoleInfo is the API representation of a role + its permissions.
type RoleInfo struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// ListRoles returns all predefined roles with their permissions.
func ListRoles() []RoleInfo {
	roles := make([]RoleInfo, 0, len(rolePermissions))
	for name, perms := range rolePermissions {
		p := make([]string, len(perms))
		copy(p, perms)
		sort.Strings(p)
		roles = append(roles, RoleInfo{Name: name, Permissions: p})
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	return roles
}

// RolePermissions returns the permission set for a role (or nil if unknown).
func RolePermissions(role string) []string {
	return rolePermissions[role]
}

// AddBinding creates a role binding.
func (s *store) AddBinding(subjectType, subjectID, role, scopeType, scopeID string) (*RoleBinding, error) {
	if rolePermissions[role] == nil {
		return nil, ErrBadRequest
	}
	if subjectID == "" {
		return nil, ErrBadRequest
	}
	b := &RoleBinding{
		ID:          randID(12),
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Role:        role,
		ScopeType:   scopeType,
		ScopeID:     scopeID,
		CreatedAt:   time.Now(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindings[b.ID] = b
	return b, nil
}

// ListBindings returns bindings filtered by subject (optional).
func (s *store) ListBindings(subjectType, subjectID string) []*RoleBinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RoleBinding, 0)
	for _, b := range s.bindings {
		if subjectType != "" && b.SubjectType != subjectType {
			continue
		}
		if subjectID != "" && b.SubjectID != subjectID {
			continue
		}
		out = append(out, b)
	}
	return out
}

// DeleteBinding removes a binding by id.
func (s *store) DeleteBinding(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.bindings[id]; !ok {
		return ErrBindingNotFound
	}
	delete(s.bindings, id)
	return nil
}

// BindingsForSubject returns all role bindings for a subject.
func (s *store) BindingsForSubject(subjectID string) []*RoleBinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RoleBinding, 0)
	for _, b := range s.bindings {
		if b.SubjectID == subjectID {
			out = append(out, b)
		}
	}
	return out
}

// AuthzResult is the response of /v1/authz.
type AuthzResult struct {
	Allow  bool     `json:"allow"`
	Reason []string `json:"reason"`
}

// Authorize decides whether subjectID may perform action on resource.
// It uses role bindings for the subject; the action must be present in the
// union of bound roles' permissions (or a role with wildcard "*").
func (s *store) Authorize(subjectID, action, resource string) (AuthzResult, *AuditEvent) {
	end := observeDBSpan(context.Background(), "bindings.forSubject")
	bindings := s.BindingsForSubject(subjectID)
	end(nil)
	reason := make([]string, 0)
	allowed := false
	for _, b := range bindings {
		perms := RolePermissions(b.Role)
		for _, p := range perms {
			if p == "*" || p == action {
				allowed = true
				reason = append(reason, "role="+b.Role+" permits "+action)
				break
			}
		}
	}
	if !allowed {
		reason = append(reason, "no binding grants "+action)
	}
	res := AuthzResult{Allow: allowed, Reason: reason}
	var ev *AuditEvent
	if !allowed {
		ev = &AuditEvent{
			ID:        randID(12),
			Type:      "auth.authz.deny",
			SubjectID: subjectID,
			Metadata:  map[string]any{"action": action, "resource": resource},
			CreatedAt: time.Now(),
		}
	}
	return res, ev
}