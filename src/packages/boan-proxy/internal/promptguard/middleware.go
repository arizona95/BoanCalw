package promptguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func InspectBody(r *http.Request) ([]Finding, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	if len(body) == 0 {
		return nil, nil
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}

	var findings []Finding

	if raw, ok := payload["prompt"]; ok {
		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			findings = append(findings, Check(text)...)
		}
	}

	if raw, ok := payload["messages"]; ok {
		var messages []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &messages); err == nil {
			for _, msg := range messages {
				if contentRaw, ok := msg["content"]; ok {
					var content string
					if err := json.Unmarshal(contentRaw, &content); err == nil {
						findings = append(findings, Check(content)...)
					}
				}
			}
		}
	}

	return findings, nil
}
