// Package model holds the types shared across the whole ingest pipeline.
package model

import "time"

// LogEntry is a normalised log line.
//
// TenantID and Redacted must NEVER come from the client, hence json:"-": the
// gateway assigns TenantID after authentication, and the redaction pipeline sets
// Redacted. This is a security decision — a client cannot declare which tenant it
// belongs to.
type LogEntry struct {
	TenantID  string         `json:"-"`
	Timestamp time.Time      `json:"ts"`
	Service   string         `json:"service"`
	Level     string         `json:"level"`
	TraceID   string         `json:"trace_id,omitempty"`
	Message   string         `json:"message"`
	Attrs     map[string]any `json:"attrs,omitempty"`

	// Redacted = true means the entry has passed through the redaction pipeline.
	// The writer MUST refuse to persist an entry with Redacted == false (see
	// writer.go), which is how the "no log is stored unredacted" invariant is
	// enforced.
	Redacted bool `json:"-"`
}

// Validate checks the required client-supplied fields.
func (e *LogEntry) Validate() error {
	if e.Service == "" {
		return ErrMissingField("service")
	}
	if e.Message == "" {
		return ErrMissingField("message")
	}
	return nil
}

// ErrMissingField is a simple validation error that maps cleanly to HTTP 400.
type ErrMissingField string

func (e ErrMissingField) Error() string { return "missing required field: " + string(e) }
