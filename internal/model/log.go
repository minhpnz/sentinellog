// Package model chứa kiểu dữ liệu dùng chung cho toàn bộ ingest pipeline.
package model

import "time"

// LogEntry là một dòng log đã chuẩn hoá.
//
// TenantID và Redacted KHÔNG được phép đến từ client (json:"-"): TenantID do
// gateway gán sau khi authenticate, Redacted do redaction pipeline đặt. Đây là
// một quyết định bảo mật — client không được tự khai mình thuộc tenant nào.
type LogEntry struct {
	TenantID  string         `json:"-"`
	Timestamp time.Time      `json:"ts"`
	Service   string         `json:"service"`
	Level     string         `json:"level"`
	TraceID   string         `json:"trace_id,omitempty"`
	Message   string         `json:"message"`
	Attrs     map[string]any `json:"attrs,omitempty"`

	// Redacted = true nghĩa là entry đã đi qua redaction pipeline. Writer PHẢI
	// từ chối ghi entry có Redacted == false (xem writer.go) — đây là cách ép
	// invariant "không log nào được persist mà chưa redact".
	Redacted bool `json:"-"`
}

// Validate kiểm tra các field bắt buộc do client cung cấp.
func (e *LogEntry) Validate() error {
	if e.Service == "" {
		return ErrMissingField("service")
	}
	if e.Message == "" {
		return ErrMissingField("message")
	}
	return nil
}

// ErrMissingField là lỗi validate đơn giản, dễ map sang HTTP 400.
type ErrMissingField string

func (e ErrMissingField) Error() string { return "missing required field: " + string(e) }
