package internal

import (
	"time"
)

// ---------------------------------------------------------------------------
// Partner API keys: high-entropy generation, hashed storage, rotation with
// dual-active window, revocation.
// ---------------------------------------------------------------------------

// APIKeyResult is returned once at creation/rotation time with full key material.
type APIKeyResult struct {
	ID         string   `json:"id"`
	PartnerID  string   `json:"partner_id"`
	Key        string   `json:"key"`
	Prefix     string   `json:"prefix"`
	Scopes     []string `json:"scopes"`
	IPAllowlist []string `json:"ip_allowlist,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// apiKeyPrefix is the stable lookup prefix (first 8 chars after "iko_").
const apiKeyPrefix = "iko_"

// generateAPIKey returns a high-entropy URL-safe key plus its prefix.
func generateAPIKey() (key, prefix string, err error) {
	key = apiKeyPrefix + randomToken(32)
	prefix = key[:len(apiKeyPrefix)+8]
	return key, prefix, nil
}

// CreateAPIKey issues a new partner API key.
func (s *store) CreateAPIKey(partnerID string, scopes, ipAllowlist []string, expiresAt *time.Time) (*APIKeyResult, *AuditEvent, error) {
	if partnerID == "" {
		return nil, nil, ErrBadRequest
	}
	key, prefix, err := generateAPIKey()
	if err != nil {
		return nil, nil, err
	}
	id := randID(12)
	now := time.Now()
	k := &APIKey{
		ID:          id,
		PartnerID:   partnerID,
		Prefix:      prefix,
		KeyHash:     sha256Hex(key),
		Scopes:      scopes,
		IPAllowlist: ipAllowlist,
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
	}
	s.mu.Lock()
	s.apiKeys[id] = k
	s.apiKeysByHash[k.KeyHash] = id
	s.mu.Unlock()
	ev := AuditEvent{
		ID:        randID(12),
		Type:      "auth.key.create",
		SubjectID: partnerID,
		Metadata:  map[string]any{"key_id": id, "prefix": prefix},
		CreatedAt: now,
	}
	res := &APIKeyResult{
		ID:          id,
		PartnerID:   partnerID,
		Key:         key,
		Prefix:      prefix,
		Scopes:      scopes,
		IPAllowlist: ipAllowlist,
		ExpiresAt:  expiresAt,
	}
	return res, &ev, nil
}

// ListAPIKeys returns metadata (prefix + scopes) for all keys of a partner.
// Full key material is never returned.
func (s *store) ListAPIKeys(partnerID string) []*APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*APIKey, 0)
	for _, k := range s.apiKeys {
		if k.PartnerID != partnerID {
			continue
		}
		out = append(out, k)
	}
	return out
}

// RotateAPIKey issues a new key for the given id, keeping the old key
// dual-active by retaining its hash in PreviousKeyHash until explicit revoke.
func (s *store) RotateAPIKey(id string) (*APIKeyResult, *AuditEvent, error) {
	key, prefix, err := generateAPIKey()
	if err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.apiKeys[id]
	if !ok {
		return nil, nil, ErrAPIKeyNotFound
	}
	if k.RevokedAt != nil {
		return nil, nil, ErrAPIKeyNotFound
	}
	// Move current to previous (dual-active). The previous key remains
	// resolvable until explicit revoke.
	k.PreviousKeyHash = k.KeyHash
	k.PreviousPrefix = k.Prefix
	now := time.Now()
	k.RotatedAt = &now
	k.KeyHash = sha256Hex(key)
	k.Prefix = prefix
	s.apiKeysByHash[k.KeyHash] = id
	if k.PreviousKeyHash != "" {
		s.apiKeysByHash[k.PreviousKeyHash] = id
	}
	ev := AuditEvent{
		ID:        randID(12),
		Type:      "auth.key.rotate",
		SubjectID: k.PartnerID,
		Metadata:  map[string]any{"key_id": id, "prefix": prefix},
		CreatedAt: now,
	}
	res := &APIKeyResult{
		ID:          id,
		PartnerID:   k.PartnerID,
		Key:         key,
		Prefix:      prefix,
		Scopes:      k.Scopes,
		IPAllowlist: k.IPAllowlist,
		ExpiresAt:   k.ExpiresAt,
	}
	return res, &ev, nil
}

// RevokeAPIKey marks the key revoked; future authz decisions deny.
func (s *store) RevokeAPIKey(id string) (*AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.apiKeys[id]
	if !ok {
		return nil, ErrAPIKeyNotFound
	}
	if k.RevokedAt != nil {
		return nil, nil
	}
	now := time.Now()
	k.RevokedAt = &now
	delete(s.apiKeysByHash, k.KeyHash)
	if k.PreviousKeyHash != "" {
		delete(s.apiKeysByHash, k.PreviousKeyHash)
	}
	ev := AuditEvent{
		ID:        randID(12),
		Type:      "auth.key.revoke",
		SubjectID: k.PartnerID,
		Metadata:  map[string]any{"key_id": id},
		CreatedAt: now,
	}
	return &ev, nil
}

// ResolveAPIKey looks up a key by full material (current or previous hash)
// and returns the key record. Used by /v1/authz for key-based subjects.
func (s *store) ResolveAPIKey(fullKey string) *APIKey {
	hash := sha256Hex(fullKey)
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.apiKeysByHash[hash]
	if !ok {
		return nil
	}
	return s.apiKeys[id]
}