package rewrite

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

type Rewriter struct {
	modelMap map[string]string
}

func New(modelMap map[string]string) *Rewriter {
	return &Rewriter{modelMap: modelMap}
}

func (rw *Rewriter) RewriteModel(requested string) string {
	if actual, ok := rw.modelMap[requested]; ok {
		return actual
	}
	return requested
}

func (rw *Rewriter) RewriteBody(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	r.Body.Close()

	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		r.Body = io.NopCloser(bytes.NewReader(raw))
		return "", nil
	}

	originalModel := ""
	if m, ok := body["model"].(string); ok {
		originalModel = m
		body["model"] = rw.RewriteModel(m)
	}

	rewritten, err := json.Marshal(body)
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(raw))
		return originalModel, nil
	}

	r.Body = io.NopCloser(bytes.NewReader(rewritten))
	r.ContentLength = int64(len(rewritten))
	r.Header.Set("Content-Type", "application/json")

	return originalModel, nil
}
