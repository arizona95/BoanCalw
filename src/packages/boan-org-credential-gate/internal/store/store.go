// Package store wraps GCP Secret Manager with a simple (org, role) →
// plaintext API. The plaintext never hits local disk — it lives only in
// memory for the duration of a resolve call.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	labelManagedBy = "managed-by"
	labelOrg       = "boan-org"
	labelRole      = "boan-role"
	managedByValue = "boan-org-credential-gate"
)

type Store struct {
	client    *secretmanager.Client
	projectID string
}

type Metadata struct {
	Role      string    `json:"role"`
	OrgID     string    `json:"org_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func New(ctx context.Context, projectID string) (*Store, error) {
	if projectID == "" {
		return nil, errors.New("projectID is required")
	}
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("secretmanager client: %w", err)
	}
	return &Store{client: client, projectID: projectID}, nil
}

func (s *Store) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

func secretName(orgID, role string) string {
	return fmt.Sprintf("boan-cred-%s-%s", sanitize(orgID), sanitize(role))
}

func sanitize(s string) string {
	// Secret Manager requires [A-Za-z0-9_-], up to 255 chars.
	out := strings.Builder{}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_' || r == '-':
			out.WriteRune(r)
		default:
			out.WriteRune('_')
		}
	}
	return out.String()
}

// Put creates the secret if missing, then adds a new version with the value.
func (s *Store) Put(ctx context.Context, orgID, role, plaintext string) (*Metadata, error) {
	if strings.TrimSpace(orgID) == "" || strings.TrimSpace(role) == "" {
		return nil, errors.New("orgID and role are required")
	}
	if plaintext == "" {
		return nil, errors.New("plaintext is required")
	}
	name := secretName(orgID, role)
	parent := fmt.Sprintf("projects/%s", s.projectID)
	fullName := fmt.Sprintf("%s/secrets/%s", parent, name)

	// Try create, ignore "already exists".
	_, err := s.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
		Parent:   parent,
		SecretId: name,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
			Labels: map[string]string{
				labelManagedBy: managedByValue,
				labelOrg:       sanitize(orgID),
				labelRole:      sanitize(role),
			},
		},
	})
	if err != nil {
		if st, ok := status.FromError(err); !ok || st.Code() != codes.AlreadyExists {
			return nil, fmt.Errorf("create secret: %w", err)
		}
	}

	_, err = s.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: fullName,
		Payload: &secretmanagerpb.SecretPayload{
			Data: []byte(plaintext),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("add secret version: %w", err)
	}

	return s.Head(ctx, orgID, role)
}

// Get returns the latest plaintext. Caller must treat the returned value
// as short-lived and never log/persist it.
func (s *Store) Get(ctx context.Context, orgID, role string) (string, error) {
	name := secretName(orgID, role)
	resp, err := s.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", s.projectID, name),
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("access secret: %w", err)
	}
	return string(resp.Payload.Data), nil
}

// Head returns metadata only (never plaintext).
func (s *Store) Head(ctx context.Context, orgID, role string) (*Metadata, error) {
	name := secretName(orgID, role)
	resp, err := s.client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s", s.projectID, name),
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get secret: %w", err)
	}
	md := &Metadata{
		Role:  role,
		OrgID: orgID,
	}
	if resp.CreateTime != nil {
		md.CreatedAt = resp.CreateTime.AsTime()
	}
	// Secret Manager doesn't expose updated; use latest version time via list.
	md.UpdatedAt = md.CreatedAt
	if ver, err := s.latestVersionTime(ctx, name); err == nil {
		md.UpdatedAt = ver
	}
	return md, nil
}

func (s *Store) latestVersionTime(ctx context.Context, name string) (time.Time, error) {
	it := s.client.ListSecretVersions(ctx, &secretmanagerpb.ListSecretVersionsRequest{
		Parent:   fmt.Sprintf("projects/%s/secrets/%s", s.projectID, name),
		PageSize: 1,
	})
	v, err := it.Next()
	if err != nil {
		return time.Time{}, err
	}
	if v.CreateTime != nil {
		return v.CreateTime.AsTime(), nil
	}
	return time.Time{}, errors.New("no version time")
}

// List returns metadata for all credentials belonging to an org.
func (s *Store) List(ctx context.Context, orgID string) ([]*Metadata, error) {
	parent := fmt.Sprintf("projects/%s", s.projectID)
	filter := fmt.Sprintf("labels.%s=%s AND labels.%s=%s",
		labelManagedBy, managedByValue,
		labelOrg, sanitize(orgID),
	)
	it := s.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent: parent,
		Filter: filter,
	})
	out := []*Metadata{}
	for {
		sec, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		role := sec.Labels[labelRole]
		md := &Metadata{Role: role, OrgID: orgID}
		if sec.CreateTime != nil {
			md.CreatedAt = sec.CreateTime.AsTime()
			md.UpdatedAt = md.CreatedAt
		}
		out = append(out, md)
	}
	return out, nil
}

// Delete removes the whole secret (all versions).
func (s *Store) Delete(ctx context.Context, orgID, role string) error {
	name := secretName(orgID, role)
	err := s.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s", s.projectID, name),
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return ErrNotFound
		}
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}

var ErrNotFound = errors.New("credential not found")
