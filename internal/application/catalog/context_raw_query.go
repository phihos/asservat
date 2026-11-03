package catalog

import (
	"context"
	"slices"
	"time"

	permissions "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
)

type rawCaseSelection struct {
	digests []artifact.Digest
	records []authorizedContext
	until   time.Time
}

// ResolveRawQuery reuses case authority and its final checks, with selected-only
// raw semantics. Private routing narrows versions before any evidence lookup;
// every selected target needs ordinary download rights, with no share fallback.
func (s ContextCaseService) ResolveRawQuery(ctx context.Context, source identities.CurrentIdentity, caseID string, digests []artifact.Digest) (permissions.RawQuerySelection, error) {
	var zero permissions.RawQuerySelection
	if len(digests) < 1 || len(digests) > authorization.GrantMaxResultArtifacts {
		return zero, value.ErrUnavailable
	}
	seen := map[artifact.Digest]bool{}
	for _, d := range digests {
		if d == (artifact.Digest{}) || seen[d] {
			return zero, value.ErrUnavailable
		}
		seen[d] = true
	}
	raw := rawCaseSelection{digests: slices.Clone(digests)}
	if _, err := s.getContextCase(ctx, source, caseID, &raw); err != nil {
		return zero, err
	}
	out := permissions.RawQuerySelection{ValidUntil: raw.until}
	for _, r := range raw.records {
		record := r.record
		output := authorization.VerifiedOutput{CaptureID: record.CaptureID, ActionID: record.ActionID, ArtifactID: r.artifact.ArtifactID, ExecutionDigest: record.ExecutionDigest, ArtifactDigest: record.Version, Target: r.artifact.Target}
		size := *record.NativeBytes
		out.Artifacts = append(out.Artifacts, authorization.RawQueryArtifact{Output: output, NativeBytes: size, ExpiresAt: r.artifact.ExpiresAt})
		out.Review = append(out.Review, permissions.RawQueryReviewArtifact{Output: output, NativeBytes: size, ExpiresAt: r.artifact.ExpiresAt, Namespace: record.Namespace, WorkloadKind: record.WorkloadKind, WorkloadName: record.WorkloadName, PodName: record.PodName, NativeType: record.NativeType})
	}
	return out, nil
}
func rawRecordValid(r permissions.ContextDownloadEvidence, route value.ContextCaseRoute, caseID string) bool {
	if r.CaseID != caseID || r.DataClass != "raw" || r.NativeBytes == nil || *r.NativeBytes < 0 || *r.NativeBytes > artifact.MaxNativeBytes || r.ExecutionDigest == (artifact.Digest{}) || !identity.Text(r.ActionID, 64) || len(r.Namespace) > 253 || len(r.WorkloadKind) > 64 || len(r.WorkloadName) > 253 || len(r.PodName) > 253 {
		return false
	}
	switch r.NativeType {
	case artifact.RawPCAPNGArtifact:
		return r.Retained.Input.EvidenceType == "packetCapture"
	case artifact.SyscallArgumentsArtifact:
		return r.Retained.Input.EvidenceType == "syscallTrace"
	case artifact.PprofArtifact, artifact.GoTraceArtifact:
		return r.Retained.Input.EvidenceType == "profile"
	default:
		return false
	}
}
