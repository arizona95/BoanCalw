package rbac

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"sync"
)

type Role string

const (
	RoleAny   Role = "any_authenticated"
	RoleDev   Role = "developer_or_admin"
	RoleAdmin Role = "admin_only"
)

type ToolPolicy struct {
	Tool string
	Role Role
}

var defaultPolicies = []ToolPolicy{
	{"read_file", RoleAny},
	{"list_files", RoleAny},
	{"search_files", RoleAny},
	{"write_file", RoleDev},
	{"edit_file", RoleDev},
	{"create_file", RoleDev},
	{"exec_cmd", RoleAdmin},
	{"bash", RoleAdmin},
	{"delete_file", RoleAdmin},
	{"admin_config", RoleAdmin},
}

type Checker struct {
	mu       sync.RWMutex
	policies map[string]Role
}

func New(extras []ToolPolicy) *Checker {
	m := make(map[string]Role)
	for _, p := range defaultPolicies {
		m[p.Tool] = p.Role
	}
	for _, p := range extras {
		m[p.Tool] = p.Role
	}
	return &Checker{policies: m}
}

var ErrForbidden = errors.New("rbac: forbidden")
var ErrUnauthenticated = errors.New("rbac: unauthenticated")

func (c *Checker) Check(r *http.Request, tool string) error {
	userRole := ExtractRole(r)
	if userRole == "" {
		return ErrUnauthenticated
	}
	return c.CheckRole(userRole, tool)
}

func (c *Checker) CheckRole(role string, tool string) error {
	c.mu.RLock()
	required, ok := c.policies[tool]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	return matchRole(strings.ToLower(role), required)
}

func (c *Checker) AddPolicy(tool string, role Role) {
	c.mu.Lock()
	c.policies[tool] = role
	c.mu.Unlock()
}

func (c *Checker) PolicyCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.policies)
}

func ExtractRole(r *http.Request) string {
	if role := r.Header.Get("X-Boan-Role"); role != "" {
		return strings.ToLower(role)
	}
	return ""
}

func safeEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

func matchRole(have string, need Role) error {
	switch need {
	case RoleAny:
		return nil
	case RoleDev:
		if safeEqual(have, "developer") || safeEqual(have, "admin") {
			return nil
		}
	case RoleAdmin:
		if safeEqual(have, "admin") {
			return nil
		}
	}
	return ErrForbidden
}
