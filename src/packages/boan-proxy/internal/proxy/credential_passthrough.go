package proxy

import "strings"

const credentialPassthroughSettingKey = "credential_passthrough"

type credentialPassthroughEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (s *Server) listCredentialPassthrough(orgID string) []credentialPassthroughEntry {
	if s == nil || s.orgSettings == nil {
		return nil
	}
	rec := s.orgSettings.GetOrCreate(orgID)
	if rec == nil || rec.Settings == nil {
		return nil
	}
	raw, ok := rec.Settings[credentialPassthroughSettingKey]
	if !ok {
		return nil
	}
	var items []interface{}
	switch typed := raw.(type) {
	case []interface{}:
		items = typed
	case []map[string]any:
		items = make([]interface{}, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
	default:
		return nil
	}
	out := make([]credentialPassthroughEntry, 0, len(items))
	for _, item := range items {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := obj["name"].(string)
		value, _ := obj["value"].(string)
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			continue
		}
		out = append(out, credentialPassthroughEntry{Name: name, Value: value})
	}
	return out
}

func (s *Server) credentialPassthroughValues(orgID string) map[string]struct{} {
	items := s.listCredentialPassthrough(orgID)
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		out[item.Value] = struct{}{}
	}
	return out
}

func (s *Server) upsertCredentialPassthrough(orgID, name, value string) error {
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if name == "" || value == "" || s == nil || s.orgSettings == nil {
		return nil
	}
	current := s.listCredentialPassthrough(orgID)
	updated := make([]map[string]any, 0, len(current)+1)
	replaced := false
	for _, item := range current {
		if strings.EqualFold(item.Name, name) {
			updated = append(updated, map[string]any{"name": name, "value": value})
			replaced = true
			continue
		}
		updated = append(updated, map[string]any{"name": item.Name, "value": item.Value})
	}
	if !replaced {
		updated = append(updated, map[string]any{"name": name, "value": value})
	}
	_, err := s.orgSettings.Patch(orgID, nil, map[string]interface{}{
		credentialPassthroughSettingKey: updated,
	})
	return err
}

func (s *Server) deleteCredentialPassthrough(orgID, name string) error {
	name = strings.TrimSpace(name)
	if name == "" || s == nil || s.orgSettings == nil {
		return nil
	}
	current := s.listCredentialPassthrough(orgID)
	updated := make([]map[string]any, 0, len(current))
	for _, item := range current {
		if strings.EqualFold(item.Name, name) {
			continue
		}
		updated = append(updated, map[string]any{"name": item.Name, "value": item.Value})
	}
	_, err := s.orgSettings.Patch(orgID, nil, map[string]interface{}{
		credentialPassthroughSettingKey: updated,
	})
	return err
}
