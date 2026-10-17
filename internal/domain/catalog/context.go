// Package catalog defines minimized authorized case views. Routing facts are
// private inputs; a case identifier or publication alone grants no readership.
package catalog

import (
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

var ErrUnavailable = errors.New("case unavailable")

const MaxContextCaseArtifacts = 100

type CaseRouteQuery struct {
	RootID, CaseID string
	Identity       identity.Identity
	Recovery       artifact.RecoveryProof
}

func (q CaseRouteQuery) Valid(now time.Time) bool {
	return authorization.UUID(q.RootID) && authorization.UUID(q.CaseID) && q.Identity.Valid(now) && slices.Contains(q.Identity.Scopes, "evidence:read") && q.Recovery.Valid(now)
}

// ContextCaseRoute contains published-only lookup keys. It is not a public DTO
// and never substitutes for ordinary scope eligibility or retained audiences.
type ContextCaseRoute struct {
	CaptureID, ArtifactID string
	Target                authorization.Target
}

func (r ContextCaseRoute) Valid() bool {
	return authorization.UUID(r.CaptureID) && authorization.UUID(r.ArtifactID) && r.Target.Valid()
}

type ContextCaseRoutes struct {
	CaseID                 string
	Routes                 []ContextCaseRoute
	ObservedAt, ValidUntil time.Time
}

func (r ContextCaseRoutes) Valid(now time.Time) bool {
	if !authorization.UUID(r.CaseID) || len(r.Routes) < 1 || len(r.Routes) > MaxContextCaseArtifacts || !identity.Fresh(r.ObservedAt, r.ValidUntil, now, 5*time.Second) {
		return false
	}
	seen := map[string]bool{}
	for _, route := range r.Routes {
		if !route.Valid() || seen[route.ArtifactID] {
			return false
		}
		seen[route.ArtifactID] = true
	}
	return true
}

// ContextCase is an ordinary metadata view, not a download or raw/shared grant.
// It carries no native checksum, filename, bytes, object locator or hidden count.
type ContextCase struct {
	CaseID                 string
	Artifacts              []ContextCaseArtifact
	ObservedAt, ValidUntil time.Time
}

type ContextCaseArtifact struct {
	ArtifactID, CaptureID string
	Target                authorization.Target // internal navigation match; omit from public DTO
	// Version is the immutable verified artifact version: SHA256 of the
	// existing versioned ciphertext-copy receipt serialization. It is NOT the native file SHA256.
	Version             artifact.Digest
	ExpiresAt, DeleteBy time.Time
}

func (c ContextCase) Valid(now time.Time) bool {
	if !authorization.UUID(c.CaseID) || len(c.Artifacts) < 1 || len(c.Artifacts) > MaxContextCaseArtifacts || !identity.Fresh(c.ObservedAt, c.ValidUntil, now, 5*time.Second) {
		return false
	}
	seen := map[string]bool{}
	for _, a := range c.Artifacts {
		if !authorization.UUID(a.ArtifactID) || !authorization.UUID(a.CaptureID) || !a.Target.Valid() || a.Version == (artifact.Digest{}) || !now.Before(a.ExpiresAt) || !a.ExpiresAt.Before(a.DeleteBy) || c.ValidUntil.After(a.ExpiresAt) || seen[a.ArtifactID] {
			return false
		}
		seen[a.ArtifactID] = true
	}
	return true
}
