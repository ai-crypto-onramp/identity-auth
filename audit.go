package main

import (
	"time"
)

// ---------------------------------------------------------------------------
// Audit log: in-memory append-only event store with thread-safe accessors.
// ---------------------------------------------------------------------------

// RecordAudit appends one or more events to the store's audit log.
func (s *store) RecordAudit(events ...*AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if ev.ID == "" {
			ev.ID = randID(12)
		}
		if ev.CreatedAt.IsZero() {
			ev.CreatedAt = time.Now()
		}
		if ev.Metadata == nil {
			ev.Metadata = map[string]any{}
		}
		s.auditEvents = append(s.auditEvents, *ev)
	}
}

// ListAudit returns a copy of all audit events (oldest first).
func (s *store) ListAudit() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEvent, len(s.auditEvents))
	copy(out, s.auditEvents)
	return out
}