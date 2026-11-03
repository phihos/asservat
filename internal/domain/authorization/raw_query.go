package authorization

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

const GrantRawQuery = "rawQuery"

// RawQueryArtifact is an existing, independently published output. NativeBytes
// is its verified plaintext length, never an estimated or configured limit.
type RawQueryArtifact struct {
	Output      VerifiedOutput
	NativeBytes int64
	ExpiresAt   time.Time
}

// RawQueryScope is a personal disclosure request, independent of collection.
// The grant's requester supplies its one exact human/client binding. Target
// authority belongs to every selected output, not a representative first item.
type RawQueryScope struct {
	CaseID        string
	Artifacts     []RawQueryArtifact
	Operations    []string
	Reason        string
	MaxBytes      int64
	MaxOperations int64
	NotAfter      time.Time
}

func (r RawQueryScope) Clone() RawQueryScope {
	r.Artifacts = slices.Clone(r.Artifacts)
	r.Operations = slices.Clone(r.Operations)
	return r
}

func (r RawQueryScope) Valid(requestedAt time.Time) bool {
	if !UUID(r.CaseID) || requestedAt.IsZero() || !identity.Text(r.Reason, 512) ||
		len(r.Artifacts) < 1 || len(r.Artifacts) > GrantMaxResultArtifacts ||
		!slices.Equal(r.Operations, []string{GrantDownloadOperation}) ||
		r.MaxBytes < 1 || r.MaxBytes > artifact.MaxNativeBytes ||
		r.MaxOperations < 1 || r.MaxOperations > GrantMaxResultOperations ||
		!r.NotAfter.After(requestedAt) || r.NotAfter.After(requestedAt.Add(GrantMaxLifetime)) {
		return false
	}
	var total int64
	previous := ""
	for _, a := range r.Artifacts {
		if !a.Output.Valid() || a.Output.ArtifactID <= previous || a.NativeBytes < 0 ||
			a.NativeBytes > artifact.MaxNativeBytes || !a.ExpiresAt.After(requestedAt) ||
			a.NativeBytes > r.MaxBytes-total {
			return false
		}
		total += a.NativeBytes
		previous = a.Output.ArtifactID
	}
	return true
}

func (g Grant) validRawQuery() bool {
	r := g.RawQuery
	if r == nil || !r.Valid(g.RequestedAt) || g.Policy != nil || !g.PolicyNotAfter.IsZero() ||
		g.Requester.Kind != identity.Human || g.PreviewID != "" || g.CaptureID != "" ||
		g.Target != (Target{}) || g.DataClass != "raw" || g.ResultAccess != nil ||
		g.ResultAccessDigest != (artifact.Digest{}) || g.Lifetime < time.Second ||
		g.Lifetime > GrantMaxLifetime || g.Lifetime%time.Second != 0 {
		return false
	}
	// The application and store verify canonical scope bytes/digest, as for
	// other grant kinds. Domain validation covers the typed value contract.
	return true
}

func (r RawQueryScope) covers(output VerifiedOutput, now time.Time) bool {
	i, found := slices.BinarySearchFunc(r.Artifacts, output.ArtifactID, func(a RawQueryArtifact, id string) int {
		if a.Output.ArtifactID < id {
			return -1
		}
		if a.Output.ArtifactID > id {
			return 1
		}
		return 0
	})
	return found && r.Artifacts[i].Output == output && now.Before(r.Artifacts[i].ExpiresAt)
}
