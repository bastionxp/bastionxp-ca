// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// JSON logs: one JSON object per line with the message and fields, and
// nothing below the level set.
func TestJSONLog(t *testing.T) {
	var out bytes.Buffer
	logger, err := newLogger(&out, "json", "info")
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("not shown")
	logger.Info("certificate issued", "template", "tls-server", "serial", "abc")
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("lines = %q, want one (debug is below info)", lines)
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, lines[0])
	}
	if entry["msg"] != "certificate issued" || entry["level"] != "INFO" || entry["serial"] != "abc" || entry["time"] == nil {
		t.Errorf("entry = %v", entry)
	}
}

// An unknown log format or level is refused; every level is accepted, in any
// case.
func TestLoggerOptions(t *testing.T) {
	for _, tt := range []struct{ format, level string }{{"xml", "info"}, {"json", "loud"}} {
		if _, err := newLogger(&bytes.Buffer{}, tt.format, tt.level); err == nil {
			t.Errorf("%s/%s: no error", tt.format, tt.level)
		}
	}
	for _, level := range []string{"debug", "info", "warn", "error", "WARN"} {
		if _, err := newLogger(&bytes.Buffer{}, "text", level); err != nil {
			t.Errorf("%s: %v", level, err)
		}
	}
}
