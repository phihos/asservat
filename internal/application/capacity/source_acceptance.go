package capacity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

const CapacitySourceFormat = "capacity-source/v1"
const CapacityAcceptedSourceFormat = "accepted-capacity-source/v1"
const CapacitySelectedSourceFormat = "capacity-selected-source/v1"
const CapacitySourceBytes = 256 << 10

// Versions includes canonical raw-spec digests even for objects whose schema
// could not be decoded. An invalid edit is therefore a known source change;
// it cannot disappear merely because its typed budget or scope is absent.
type CapacitySourceVersion struct {
	Kind, Name, UID string
	Generation      int64
	Deleting        bool
	Spec            artifact.Digest
}

func sourceVersion(r cfg.Resource, d artifact.Digest) CapacitySourceVersion {
	return CapacitySourceVersion{r.Kind, r.Name, r.UID, r.Generation, r.Deleting, d}
}
func sortedSourceVersions(in []CapacitySourceVersion) []CapacitySourceVersion {
	out := append(make([]CapacitySourceVersion, 0, len(in)), in...)
	slices.SortFunc(out, func(a, b CapacitySourceVersion) int {
		if a.Kind < b.Kind {
			return -1
		}
		if a.Kind > b.Kind {
			return 1
		}
		if a.UID < b.UID {
			return -1
		}
		if a.UID > b.UID {
			return 1
		}
		return 0
	})
	return out
}

type capacityDesiredPool struct {
	StorageProfile, Assurance string
	Budget                    *PoolBudgetInput
}
type capacityDesiredPolicy struct {
	SourceResources *SourceResourceLimits `json:",omitempty"`
	Pool            string
	Scope           *BudgetScope
	Budget          *PolicyBudgetInput
}
type capacityDesiredVersion struct {
	Version CapacitySourceVersion
	Pool    *capacityDesiredPool   `json:",omitempty"`
	Policy  *capacityDesiredPolicy `json:",omitempty"`
}

func capacityDesiredBytes(format string, s CapacitySnapshot, versions []CapacitySourceVersion) ([]byte, error) {
	entries := make([]capacityDesiredVersion, 0, len(versions))
	for _, v := range sortedSourceVersions(versions) {
		x := capacityDesiredVersion{Version: v}
		if v.Kind == "EvidenceStoragePool" {
			for _, p := range s.Pools {
				if p.Resource.UID == v.UID {
					x.Pool = &capacityDesiredPool{p.StorageProfile, p.Assurance, p.Budget}
					break
				}
			}
		} else {
			for _, p := range s.Policies {
				if p.Resource.UID == v.UID {
					x.Policy = &capacityDesiredPolicy{Pool: p.Pool, Scope: p.Scope, Budget: p.Budget}
					if format != CapacitySelectedSourceFormat {
						x.Policy.SourceResources = p.SourceResources
					}
					break
				}
			}
		}
		if (x.Pool == nil) == (x.Policy == nil) {
			return nil, cfg.ErrUnavailable
		}
		entries = append(entries, x)
	}
	b, e := json.Marshal(struct {
		Format, Cluster, ControlUID string
		Entries                     []capacityDesiredVersion
	}{format, s.ClusterID, s.ControlNamespace.UID, entries})
	if e != nil || len(b) > CapacitySourceBytes {
		return nil, cfg.ErrUnavailable
	}
	return b, nil
}

func capacityDesiredDigest(format string, s CapacitySnapshot, versions []CapacitySourceVersion) (artifact.Digest, error) {
	b, e := capacityDesiredBytes(format, s, versions)
	if e != nil {
		return artifact.Digest{}, e
	}
	return sha256.Sum256(b), nil
}

// CapacitySourceDigest is shared by observation and SQL acceptance. It excludes
// observation/resourceVersion/status only; complete membership, exact immutable
// identity, generation, deleting state and canonical desired bytes remain bound.
// A nil result is never an accepted empty or unchanged source.
func CapacitySourceDigest(s CapacitySnapshot, versions []CapacitySourceVersion) (artifact.Digest, error) {
	if !s.Valid(s.ObservedAt) || len(versions) != len(s.Pools)+len(s.Policies) {
		return artifact.Digest{}, cfg.ErrUnavailable
	}
	refs := make(map[string]cfg.Resource, len(versions))
	for _, p := range s.Pools {
		refs[p.Resource.UID] = p.Resource
	}
	for _, p := range s.Policies {
		refs[p.Resource.UID] = p.Resource
	}
	for _, v := range versions {
		r, ok := refs[v.UID]
		if !ok || v.Spec == (artifact.Digest{}) || sourceVersion(r, v.Spec) != v || r.SpecDigest != (artifact.Digest{}) && r.SpecDigest != v.Spec {
			return artifact.Digest{}, cfg.ErrUnavailable
		}
		delete(refs, v.UID)
	}
	if len(refs) != 0 {
		return artifact.Digest{}, cfg.ErrUnavailable
	}
	return capacityDesiredDigest(CapacitySourceFormat, s, versions)
}
func (s CapacitySourceObservation) Valid(now time.Time) bool {
	if !s.Snapshot.Valid(now) {
		return false
	}
	d, e := CapacitySourceDigest(s.Snapshot, s.Versions)
	return e == nil && d == s.Digest
}

// AcceptedCapacitySource is returned only by the fixed protected source writer.
// This is still a current observation, not acquisition authority. SQL checks its
// own source/permission/recovery state under locks for every configuration effect.
type AcceptedCapacitySource struct {
	Format, RootID, InstallationID, QualificationID string
	Revision                                        int64
	QualificationDigest, ProtectionDigest           artifact.Digest
	Observation                                     CapacitySourceObservation
	ObservedAt, FreshUntil                          time.Time
}

func (s AcceptedCapacitySource) Valid(now time.Time) bool {
	return s.Format == CapacityAcceptedSourceFormat && authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && authorization.UUID(s.QualificationID) && s.Revision > 0 && s.Revision < 1<<60 && s.QualificationDigest != (artifact.Digest{}) && s.ProtectionDigest != (artifact.Digest{}) && s.Observation.Valid(now) && identity.Fresh(s.ObservedAt, s.FreshUntil, now, CapacitySourceInterval) && !s.ObservedAt.Before(s.Observation.Snapshot.ObservedAt) && !s.FreshUntil.After(s.Observation.Snapshot.FreshUntil)
}

// CurrentSourceResources exposes only a copy from this original accepted/current
// source. It is an administrator resource observation, never an acquisition
// permit; positive team observation credit and original authority ends remain
// mandatory at the future source admission boundary.
func (s AcceptedCapacitySource) CurrentSourceResources(now time.Time, policy string) (SourceResourceLimits, error) {
	if !s.Valid(now) {
		return SourceResourceLimits{}, cfg.ErrUnavailable
	}
	for _, p := range s.Observation.Snapshot.Policies {
		if p.Resource.Name != policy {
			continue
		}
		if p.Resource.Deleting || p.Budget == nil {
			return SourceResourceLimits{}, cfg.ErrUnavailable
		}
		if p.SourceResources == nil {
			return SourceResourceLimits{}, nil
		}
		limits := *p.SourceResources
		if !limits.Node.Valid() || !limits.Workload.Valid() {
			return SourceResourceLimits{}, cfg.ErrUnavailable
		}
		return limits, nil
	}
	return SourceResourceLimits{}, cfg.ErrUnavailable
}

type CapacitySourceAcceptance struct {
	RootID, InstallationID, QualificationID string
	QualificationDigest                     artifact.Digest
	ExpectedRevision                        int64
	Observation                             CapacitySourceObservation
	Protection                              CapacitySourceProtection
	Recovery                                artifact.RecoveryProof
}

func (s CapacitySourceAcceptance) Valid(now time.Time) bool {
	return authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && authorization.UUID(s.QualificationID) && s.QualificationDigest != (artifact.Digest{}) && s.ExpectedRevision >= 0 && s.ExpectedRevision < 1<<60 && s.Observation.Valid(now) && s.Protection.Valid(now) && s.Recovery.Valid(now) && s.Recovery.InstallationID == s.InstallationID && s.Protection.ClusterID == s.Observation.Snapshot.ClusterID && s.Protection.ControlNamespaceUID == s.Observation.Snapshot.ControlNamespace.UID
}

type CapacitySourceJournal interface {
	// Returns only the current CAS sequence, including when suspended/expired.
	// It neither refreshes the source nor authorizes an enrollment effect.
	ReadCapacitySourceRevision(context.Context, artifact.RecoveryProof) (int64, error)
	AcceptCapacitySource(context.Context, CapacitySourceAcceptance) (AcceptedCapacitySource, error)
	// A known failed/changed observation fences new effects without removing
	// accepted membership, hierarchy rows, charges or original phase facts.
	InvalidateCapacitySource(context.Context, string, int64, artifact.RecoveryProof, time.Time, time.Time) error
}

// SelectedCapacitySourceDigest binds the selected pool and every assigned
// policy. It intentionally excludes unrelated pools, observation/list versions,
// and the latest global acceptance sequence. Partial enrollment may continue
// under a newer complete observation only if this exact backed source agrees.
// No policy filtering by today's matching namespace is done here: all of the
// selected pool's protected slot commitments are included.
func SelectedCapacitySourceDigest(s CapacitySnapshot, poolName string) (artifact.Digest, error) {
	b, e := capacitySelectedSourceBytes(s, poolName)
	if e != nil {
		return artifact.Digest{}, e
	}
	return sha256.Sum256(b), nil
}
func capacitySelectedSourceBytes(s CapacitySnapshot, poolName string) ([]byte, error) {
	if !s.Valid(s.ObservedAt) {
		return nil, cfg.ErrUnavailable
	}
	var pool *PoolObservation
	for i := range s.Pools {
		if s.Pools[i].Resource.Name == poolName {
			pool = &s.Pools[i]
			break
		}
	}
	if pool == nil || pool.Budget == nil || pool.Resource.Deleting || pool.Resource.SpecDigest == (artifact.Digest{}) || pool.Assurance != "qualifiedReservedBackend" {
		return nil, cfg.ErrUnavailable
	}
	versions := []CapacitySourceVersion{sourceVersion(pool.Resource, pool.Resource.SpecDigest)}
	inputs := make([]PolicyBudgetInput, 0, len(s.Policies))
	for _, p := range s.Policies {
		if p.Pool != poolName {
			continue
		}
		if p.Budget == nil || p.Scope == nil || !p.Scope.valid() || p.Resource.Deleting || p.Resource.SpecDigest == (artifact.Digest{}) || p.Budget.Name != p.Resource.Name || p.Budget.Pool != poolName || p.Budget.Cluster != p.Scope.ClusterID {
			return nil, cfg.ErrUnavailable
		}
		inputs = append(inputs, *p.Budget)
		versions = append(versions, sourceVersion(p.Resource, p.Resource.SpecDigest))
	}
	if _, e := CompileProtectedPool(*pool.Budget, inputs); e != nil {
		return nil, e
	}
	return capacityDesiredBytes(CapacitySelectedSourceFormat, s, versions)
}
