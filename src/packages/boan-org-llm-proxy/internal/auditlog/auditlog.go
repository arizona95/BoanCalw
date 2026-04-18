// Package auditlog emits structured JSON log lines that Cloud Run
// automatically ingests into Cloud Logging. Every security-relevant event
// (forward, resolve, revoke, auth-reject) should go through here so that
// the org's audit trail is queryable and exportable.
package auditlog

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Event struct {
	Timestamp  string `json:"ts"`
	Service    string `json:"service"`
	EventType  string `json:"event"`
	OrgID      string `json:"org_id,omitempty"`
	Role       string `json:"role,omitempty"`
	DeviceID   string `json:"device_id,omitempty"`
	CallerID   string `json:"caller_id,omitempty"`
	TargetHost string `json:"target_host,omitempty"`
	Status     int    `json:"status,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Bytes      int    `json:"bytes,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

var service = "boan-org-llm-proxy"

func SetService(name string) {
	service = name
}

// Emit writes a JSON line to stderr (Cloud Run captures it).
// Missing severity defaults to INFO.
func Emit(e Event) {
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.Service == "" {
		e.Service = service
	}
	if e.Severity == "" {
		e.Severity = "INFO"
	}
	raw, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"ts":%q,"service":%q,"event":"audit_marshal_error","severity":"ERROR","reason":%q}`+"\n",
			time.Now().UTC().Format(time.RFC3339Nano), service, err.Error())
		return
	}
	fmt.Fprintln(os.Stderr, string(raw))
}
