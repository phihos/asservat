package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

type projectionFixture struct {
	now         time.Time
	identity    identity.Identity
	permission  value.Projection
	record      ContextProjectionEvidence
	retention   privacy.RetainedResolution
	environment analysis.ContextProjectionEnvironment
	calls       []string
	counts      map[string]int
	on          func(context.Context, string, int)
	fail        string
	origins     [][]artifact.RetentionRule
	evidence    []ContextProjectionEvidence
	artifacts   []string
	actors      []identity.Principal
}

func (f *projectionFixture) step(ctx context.Context, name string) error {
	f.calls = append(f.calls, name)
	f.counts[name]++
	if f.on != nil {
		f.on(ctx, name, f.counts[name])
	}
	if f.fail == name {
		return errors.New("private provider details")
	}
	return ctx.Err()
}
func (f *projectionFixture) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	e := f.step(ctx, "identity")
	return f.identity, e
}
func (f *projectionFixture) Permissions(ctx context.Context, target value.Target) (value.Projection, error) {
	e := f.step(ctx, "permissions")
	if target != f.permission.Target {
		return value.Projection{}, errors.New("unexpected target")
	}
	return f.permission, e
}
func (f *projectionFixture) ContextProjectionEvidence(ctx context.Context, id string) (ContextProjectionEvidence, error) {
	f.artifacts = append(f.artifacts, id)
	e := f.step(ctx, "catalog")
	return f.record, e
}
func (f *projectionFixture) ResolveRetained(ctx context.Context, input privacy.Input, previous privacy.Deadlines, origins []artifact.RetentionRule) (privacy.RetainedResolution, error) {
	f.origins = append(f.origins, slices.Clone(origins))
	e := f.step(ctx, "retention")
	if !reflect.DeepEqual(input, f.record.Retained.Input) || previous != f.record.Retained.Effective {
		return privacy.RetainedResolution{}, errors.New("changed original retention inputs")
	}
	return f.retention, e
}
func (f *projectionFixture) ProjectionEnvironment(ctx context.Context, record ContextProjectionEvidence, actor identity.Principal) (analysis.ContextProjectionEnvironment, error) {
	f.evidence = append(f.evidence, cloneProjectionEvidence(record))
	f.actors = append(f.actors, actor)
	e := f.step(ctx, "environment")
	return f.environment, e
}

func projectionTestID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func newProjectionFixture() (*projectionFixture, ContextProjectionAuthority, analysis.ContextProjectionScope) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	rev := func(n int) identity.Revision {
		return identity.Revision{UID: projectionTestID(n), Generation: 1, Digest: artifact.Digest{byte(n)}}
	}
	actor := identity.Principal{Issuer: "https://issuer.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}
	target := value.Target{ClusterID: projectionTestID(2), NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}
	scope := analysis.ContextProjectionScope{RootID: projectionTestID(1), CaseID: projectionTestID(3), CaptureID: projectionTestID(4), ArtifactID: projectionTestID(5), ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, PodUID: target.PodUID, Version: artifact.Digest{6}, SourceProjectionDigest: analysis.ContextSourceProjectionDigest(), SourceFormat: artifact.ContextFormat, DisplayVersion: analysis.ContextDisplayVersion, Selection: analysis.LineSelection{LineStart: 1, MaxLines: 200}, Principal: actor}
	reg := artifact.Registration{Location: artifact.Location{ClusterID: target.ClusterID, ArtifactID: scope.ArtifactID, AttemptID: projectionTestID(7)}, StoreID: projectionTestID(8), AllocationID: projectionTestID(9), PoolRevision: 1, AllocationRevision: 1, NativeLimit: artifact.MaxContextBytes, AnchorAt: n.Add(-time.Minute), WriteUntil: n.Add(-time.Second), ExpiresAt: n.Add(time.Hour), DeleteBy: n.Add(2 * time.Hour)}
	audience := artifact.AudienceAssignment{Kind: "Group", Issuer: actor.Issuer, SubjectID: "team", Role: "evidence-reader", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{10}, AssignmentID: projectionTestID(11)}
	refs := []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{12}}, {UID: "previously-applied", Generation: 2, Digest: artifact.Digest{13}}}
	deadlines := privacy.Deadlines{AnchorAt: reg.AnchorAt, ExpiresAt: reg.ExpiresAt, DeleteBy: reg.DeleteBy}
	proof := artifact.RetentionProof{RootID: scope.RootID, ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, PodUID: target.PodUID, Topology: rev(14), Policy: rev(15), Selectors: rev(16), SourceCount: 1, ObservedAt: n, ValidUntil: n.Add(5 * time.Second), Sources: [2]artifact.RetentionSourceVersion{{ClusterID: target.ClusterID, ControlNamespaceUID: "control", Epoch: projectionTestID(17), Hub: true, ProtectionDigest: artifact.Digest{18}, SnapshotDigest: artifact.Digest{19}, Acceptance: rev(20)}}}
	f := &projectionFixture{now: n, counts: map[string]int{},
		identity:   identity.Identity{Principal: actor, Policy: rev(21), Groups: []string{"team"}, Scopes: []string{"evidence:read"}, VerifiedAt: n, ValidUntil: n.Add(30 * time.Second)},
		permission: value.Projection{Target: target, Revision: rev(22), ObservedAt: n, FreshUntil: n.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: n, DeniesFreshUntil: n.Add(5 * time.Second), Allows: []value.CurrentAssignment{{Audience: audience, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}}},
		record:     ContextProjectionEvidence{CaseID: scope.CaseID, CaptureID: scope.CaptureID, PurposeRef: "diagnostics", Version: scope.Version, SourceFormat: scope.SourceFormat, SourceProjectionDigest: scope.SourceProjectionDigest, DataClass: "metadata", Audience: []artifact.AudienceAssignment{audience}, ObservedAt: n, ValidUntil: n.Add(5 * time.Second), Retained: privacy.RetainedArtifact{RootID: scope.RootID, Registration: reg, Input: privacy.Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: 3600, AnchorAt: reg.AnchorAt}, OriginPolicies: refs, Effective: deadlines}},
		retention:  privacy.RetainedResolution{Target: target, PolicyRevision: proof.Policy, PurposeRef: "diagnostics", Policies: slices.Clone(refs), Deadlines: deadlines, ValidUntil: n.Add(5 * time.Second), Proof: proof},
		environment: analysis.ContextProjectionEnvironment{RootID: scope.RootID, InstallationID: scope.RootID, Region: "region", StoreID: reg.StoreID, Location: reg.Location, Principal: actor, PolicyRevision: rev(23), ObservedAt: n, ValidUntil: n.Add(5 * time.Second),
			Recovery:   artifact.RecoveryProof{InstallationID: scope.RootID, IssuerEpoch: projectionTestID(24), Revision: rev(25), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)},
			Processing: artifact.DownloadProcessingProof{RootID: scope.RootID, Epoch: projectionTestID(26), CaptureID: scope.CaptureID, Location: reg.Location, Sequence: 1, StateDigest: artifact.Digest{27}, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)},
			Path:       analysis.ContextProjectionPath{Purpose: analysis.ContextProjectionPurpose, ID: projectionTestID(28), TargetClusterID: target.ClusterID, StoreID: reg.StoreID, StorageRegion: "region", AcquisitionClusterID: projectionTestID(29), AcquisitionRegion: "region", ConnectorClusterID: projectionTestID(29), ConnectorRegion: "region", HubClusterID: projectionTestID(30), HubRegion: "region", WorkerConfiguration: rev(31), HubConfiguration: rev(32)}},
	}
	return f, ContextProjectionAuthority{RootID: scope.RootID, Permissions: f, Catalog: f, Retention: f, Environment: f, Now: func() time.Time { return f.now }}, scope
}

func TestContextProjectionAuthorityReadWithoutDownload(t *testing.T) {
	f, s, scope := newProjectionFixture()
	out, err := s.CheckProjectionCurrent(context.Background(), f, scope)
	if err != nil || !out.Valid(f.now) || out.Scope != scope || out.Environment != f.environment || out.Retention != f.retention.Proof || !out.AccessUntil.Equal(f.retention.ExpiresAt) || !out.DeleteBy.Equal(f.retention.DeleteBy) {
		t.Fatalf("ordinary read failed: %v %+v", err, out)
	}
	if slices.Contains(f.identity.Scopes, "evidence:download") || !reflect.DeepEqual(f.calls, []string{"identity", "permissions", "catalog", "retention", "environment", "identity", "permissions", "retention", "environment", "identity"}) {
		t.Fatalf("wrong authority sequence: %v", f.calls)
	}
	for _, origins := range f.origins {
		if !slices.Equal(origins, f.record.Retained.OriginPolicies) {
			t.Fatal("lost a retained policy origin")
		}
	}
	for _, record := range f.evidence {
		if !reflect.DeepEqual(record, f.record) {
			t.Fatal("environment received a substituted source")
		}
	}
	if !slices.Equal(f.artifacts, []string{scope.ArtifactID}) || !slices.Equal(f.actors, []identity.Principal{scope.Principal, scope.Principal}) {
		t.Fatal("source lookup or environment changed the requested artifact/actor")
	}
	// A bounded selection and its exact query purpose are part of the decision.
	scope.Selection = analysis.LineSelection{LineStart: 3, MaxLines: 2}
	next, err := s.CheckProjectionCurrent(context.Background(), f, scope)
	if err != nil || next.DecisionDigest == out.DecisionDigest {
		t.Fatalf("selection did not bind decision: %v", err)
	}
}

func TestContextProjectionAuthorityResolvesOnlyAfterEligibility(t *testing.T) {
	f, s, scope := newProjectionFixture()
	candidate := scope.Candidate()
	// The first request supplies no source/copy version. Only protected catalog
	// publication fixes those fields, and later checks retain the exact version.
	f.record.Version = artifact.Digest{88}
	out, err := s.ResolveProjectionCurrent(context.Background(), f, candidate)
	if err != nil || !out.Valid(f.now) || out.Scope.Version != f.record.Version || out.Scope.SourceProjectionDigest != analysis.ContextSourceProjectionDigest() || f.calls[0] != "identity" || f.calls[1] != "permissions" || f.calls[2] != "catalog" {
		t.Fatalf("initial source resolution failed: %v %v", err, f.calls)
	}
	if _, err := s.CheckProjectionCurrent(context.Background(), f, scope); err == nil {
		t.Fatal("accepted substituted version on an existing scope")
	}
	for _, name := range []string{"deny", "download-only", "wrong-case", "raw-source"} {
		t.Run(name, func(t *testing.T) {
			f, s, scope := newProjectionFixture()
			switch name {
			case "deny":
				f.permission.Denies = slices.Clone(f.permission.Allows)
			case "download-only":
				f.identity.Scopes = []string{"evidence:download"}
			case "wrong-case":
				f.record.CaseID = projectionTestID(99)
			case "raw-source":
				f.record.DataClass = "raw"
			}
			out, err := s.ResolveProjectionCurrent(context.Background(), f, scope.Candidate())
			if err == nil || out != (analysis.ContextProjectionAuthority{}) {
				t.Fatal("resolved an unavailable source")
			}
			if (name == "deny" || name == "download-only") && f.counts["catalog"] != 0 {
				t.Fatal("lookup before ordinary eligibility")
			}
		})
	}
}

func TestContextProjectionAuthorityDeniesBeforeCatalog(t *testing.T) {
	for _, name := range []string{"identity", "different-client", "download-only", "no-allow", "unknown-denies", "explicit-deny", "stale-denies", "wrong-root", "raw-source", "wrong-display"} {
		t.Run(name, func(t *testing.T) {
			f, s, scope := newProjectionFixture()
			switch name {
			case "identity":
				f.fail = "identity"
			case "different-client":
				f.identity.Principal.ClientID = "other-client"
			case "download-only":
				f.identity.Scopes = []string{"evidence:download"}
			case "no-allow":
				f.permission.Allows = nil
			case "unknown-denies":
				f.permission.DeniesComplete = false
			case "explicit-deny":
				f.permission.Denies = slices.Clone(f.permission.Allows)
			case "stale-denies":
				f.permission.DeniesFreshUntil = f.now
			case "wrong-root":
				scope.RootID = projectionTestID(99)
			case "raw-source":
				scope.SourceFormat = "arbitrary-memory/v1"
			case "wrong-display":
				scope.DisplayVersion = "raw-json/v1"
			}
			out, err := s.CheckProjectionCurrent(context.Background(), f, scope)
			if err == nil || out != (analysis.ContextProjectionAuthority{}) || f.counts["catalog"] != 0 || f.counts["environment"] != 0 {
				t.Fatalf("denied request reached protected data: %v %v", err, f.calls)
			}
		})
	}
}

func TestContextProjectionAuthorityRejectsSourceSubstitution(t *testing.T) {
	for _, name := range []string{"case", "capture", "ciphertext-version", "projection", "format", "raw-class", "artifact", "target", "store", "attempt", "limit", "classification", "unretained-audience", "replaced-assignment", "expired", "catalog-deadline"} {
		t.Run(name, func(t *testing.T) {
			f, s, scope := newProjectionFixture()
			switch name {
			case "case":
				f.record.CaseID = projectionTestID(99)
			case "capture":
				f.record.CaptureID = projectionTestID(99)
			case "ciphertext-version":
				f.record.Version = artifact.Digest{99}
			case "projection":
				f.record.SourceProjectionDigest = artifact.Digest{99}
			case "format":
				f.record.SourceFormat = "unqualified/v1"
			case "raw-class":
				f.record.DataClass = "raw"
			case "artifact":
				f.record.Retained.Registration.Location.ArtifactID = projectionTestID(99)
			case "target":
				f.record.Retained.Input.Target.PodUID = "replacement-pod"
			case "store":
				f.record.Retained.Registration.StoreID = projectionTestID(99)
			case "attempt":
				f.record.Retained.Registration.Location.AttemptID = projectionTestID(99)
			case "limit":
				f.record.Retained.Registration.NativeLimit++
			case "classification":
				f.record.Retained.Input.PrivacyClass = "verifiedNonPersonal"
			case "unretained-audience":
				f.record.Audience[0].SubjectID = "other-team"
			case "replaced-assignment":
				f.permission.Allows[0].Audience.AssignmentID = projectionTestID(99)
			case "expired":
				f.record.Retained.Effective.ExpiresAt = f.now
			case "catalog-deadline":
				f.record.ValidUntil = f.now
			}
			if out, err := s.CheckProjectionCurrent(context.Background(), f, scope); err == nil || out != (analysis.ContextProjectionAuthority{}) {
				t.Fatalf("accepted substituted source: %v", err)
			}
		})
	}
}

func TestContextProjectionAuthorityRechecksAfterBlockingReads(t *testing.T) {
	for _, name := range []string{"deny", "permission-revision", "groups", "scopes", "identity-policy", "recovery", "processing", "path", "environment-policy", "retention-cutoff", "retention-source", "retention-origins", "final-identity", "final-environment"} {
		t.Run(name, func(t *testing.T) {
			f, s, scope := newProjectionFixture()
			f.on = func(_ context.Context, port string, count int) {
				if port == "environment" && count == 1 {
					switch name {
					case "deny":
						f.permission.Denies = slices.Clone(f.permission.Allows)
					case "permission-revision":
						f.permission.Revision.Generation++
					case "groups":
						f.identity.Groups[0] = "new-team"
					case "scopes":
						f.identity.Scopes = append(f.identity.Scopes, "evidence:download")
					case "identity-policy":
						f.identity.Policy.Generation++
					}
				}
				if port == "permissions" && count == 2 {
					switch name {
					case "recovery":
						f.environment.Recovery.IssuerEpoch = projectionTestID(99)
					case "processing":
						f.environment.Processing.Sequence++
					case "path":
						f.environment.Path.HubRegion = "other-region"
					case "environment-policy":
						f.environment.PolicyRevision.Generation++
					case "retention-cutoff":
						f.retention.ExpiresAt = f.now.Add(time.Minute)
					case "retention-source":
						f.retention.Proof.Sources[0].Epoch = projectionTestID(99)
					case "retention-origins":
						f.retention.Policies = f.retention.Policies[:1]
					}
				}
				if port == "environment" && count == 2 && name == "final-environment" {
					f.environment = analysis.ContextProjectionEnvironment{}
				}
				if port == "identity" && count == 3 && name == "final-identity" {
					f.identity.Scopes = nil
				}
			}
			if out, err := s.CheckProjectionCurrent(context.Background(), f, scope); err == nil || out != (analysis.ContextProjectionAuthority{}) {
				t.Fatalf("authority change passed: %v %v", err, f.calls)
			}
		})
	}
}

func TestContextProjectionAuthorityRequiresEveryProof(t *testing.T) {
	for _, name := range []string{"recovery", "processing", "wrong-processing-capture", "path", "download-purpose", "retention", "retention-target", "retention-extension", "retention-purpose", "environment", "catalog", "permissions", "retention-error"} {
		t.Run(name, func(t *testing.T) {
			f, s, scope := newProjectionFixture()
			switch name {
			case "recovery":
				f.environment.Recovery = artifact.RecoveryProof{}
			case "processing":
				f.environment.Processing = artifact.DownloadProcessingProof{}
			case "wrong-processing-capture":
				f.environment.Processing.CaptureID = projectionTestID(99)
			case "path":
				f.environment.Path = analysis.ContextProjectionPath{}
			case "download-purpose":
				f.environment.Path.Purpose = "download-artifact/v1"
			case "retention":
				f.retention.Proof = artifact.RetentionProof{}
			case "retention-target":
				f.retention.Proof.PodUID = "replacement"
			case "retention-extension":
				f.retention.DeleteBy = f.retention.DeleteBy.Add(time.Minute)
			case "retention-purpose":
				f.retention.PurposeRef = "other-purpose"
			case "retention-error":
				f.fail = "retention"
			default:
				f.fail = name
			}
			out, err := s.CheckProjectionCurrent(context.Background(), f, scope)
			if err == nil || out != (analysis.ContextProjectionAuthority{}) || strings.Contains(err.Error(), "private") {
				t.Fatalf("missing proof or private error escaped: %v", err)
			}
		})
	}
}

func TestContextProjectionAuthorityKeepsOriginalIntervals(t *testing.T) {
	for _, bound := range []string{"identity", "permission", "denies", "catalog", "retention", "environment", "request"} {
		for _, expire := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/expire=%v", bound, expire), func(t *testing.T) {
				f, s, scope := newProjectionFixture()
				until := f.now.Add(time.Second)
				ctx := context.Background()
				switch bound {
				case "identity":
					f.identity.ValidUntil = until
				case "permission":
					f.permission.Allows[0].FreshUntil = until
				case "denies":
					f.permission.DeniesFreshUntil = until
				case "catalog":
					f.record.ValidUntil = until
				case "retention":
					f.retention.ValidUntil = until
				case "environment":
					f.environment.ValidUntil = until
				case "request":
					var cancel context.CancelFunc
					ctx, cancel = context.WithDeadline(ctx, until)
					defer cancel()
				}
				f.on = func(call context.Context, port string, count int) {
					if port != "identity" || count != 2 {
						return
					}
					if deadline, ok := call.Deadline(); !ok || deadline.After(until) {
						t.Fatal("a blocking reader received a renewed original interval")
					}
					if expire {
						f.now = until
					}
					// A later read can return matching identities with fresh intervals;
					// it must not replace the original observations already consumed.
					f.identity.VerifiedAt, f.identity.ValidUntil = f.now, f.now.Add(30*time.Second)
					f.permission.ObservedAt, f.permission.FreshUntil = f.now, f.now.Add(30*time.Second)
					f.permission.DeniesObservedAt, f.permission.DeniesFreshUntil = f.now, f.now.Add(5*time.Second)
					f.permission.Allows[0].ObservedAt, f.permission.Allows[0].FreshUntil = f.now, f.now.Add(30*time.Second)
					f.retention.Proof.ObservedAt, f.retention.Proof.ValidUntil = f.now, f.now.Add(5*time.Second)
					f.retention.ValidUntil = f.now.Add(5 * time.Second)
					f.environment.ObservedAt, f.environment.ValidUntil = f.now, f.now.Add(5*time.Second)
					f.environment.Recovery.ObservedAt, f.environment.Recovery.FreshUntil = f.now, f.now.Add(5*time.Second)
					f.environment.Processing.ObservedAt, f.environment.Processing.ValidUntil = f.now, f.now.Add(5*time.Second)
				}
				out, err := s.CheckProjectionCurrent(ctx, f, scope)
				if expire {
					if err == nil || out != (analysis.ContextProjectionAuthority{}) {
						t.Fatal("refreshed an expired original observation")
					}
				} else if err != nil || !out.ValidUntil.Equal(until) {
					t.Fatalf("lost original interval: %v %v", err, out.ValidUntil)
				}
			})
		}
	}
}

func TestContextProjectionAuthorityCancellationAndDependencies(t *testing.T) {
	for _, which := range []string{"nil-context", "cancelled", "identity", "permissions", "catalog", "retention", "environment", "now"} {
		t.Run(which, func(t *testing.T) {
			f, s, scope := newProjectionFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch which {
			case "nil-context":
				ctx = nil
			case "cancelled":
				cancel()
			case "permissions":
				s.Permissions = nil
			case "catalog":
				s.Catalog = nil
			case "retention":
				s.Retention = nil
			case "environment":
				s.Environment = nil
			case "now":
				s.Now = nil
			}
			if which == "identity" {
				if _, err := s.CheckProjectionCurrent(ctx, nil, scope); err == nil {
					t.Fatal("accepted missing current identity")
				}
			} else if _, err := s.CheckProjectionCurrent(ctx, f, scope); err == nil {
				t.Fatal("accepted missing dependency")
			}
			if len(f.calls) != 0 {
				t.Fatalf("unavailable request performed reads: %v", f.calls)
			}
		})
	}
	t.Run("original-request-deadline-interrupts-catalog", func(t *testing.T) {
		f, s, scope := newProjectionFixture()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()
		f.on = func(ctx context.Context, port string, _ int) {
			if port == "catalog" {
				<-ctx.Done()
			}
		}
		if out, err := s.CheckProjectionCurrent(ctx, f, scope); err == nil || out != (analysis.ContextProjectionAuthority{}) || f.counts["retention"] != 0 {
			t.Fatal("continued after cancelled blocking catalog")
		}
	})
	t.Run("cancel-during-environment", func(t *testing.T) {
		f, s, scope := newProjectionFixture()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.on = func(_ context.Context, port string, _ int) {
			if port == "environment" {
				cancel()
			}
		}
		if out, err := s.CheckProjectionCurrent(ctx, f, scope); err == nil || out != (analysis.ContextProjectionAuthority{}) || f.counts["identity"] != 1 {
			t.Fatal("continued after cancelled environment")
		}
	})
}

// Installed native86: the decision ended 1.27 s after its check at the
// retention proof's end, which the report did not name. The decision now
// carries the component whose interval ended it, for the report only.
func TestContextProjectionAuthorityNamesItsEarliestBound(t *testing.T) {
	for _, c := range []struct {
		bound string
		set   func(*projectionFixture)
	}{
		{"retention", func(f *projectionFixture) { f.retention.ValidUntil = f.now.Add(2 * time.Second) }},
		{"environment/recovery", func(f *projectionFixture) {
			f.environment.Recovery.FreshUntil = f.now.Add(time.Second)
			f.environment.ValidUntil = f.environment.Recovery.FreshUntil
		}},
		{"catalog", func(f *projectionFixture) { f.record.ValidUntil = f.now.Add(time.Second) }},
	} {
		t.Run(c.bound, func(t *testing.T) {
			f, s, scope := newProjectionFixture()
			c.set(f)
			out, err := s.CheckProjectionCurrent(context.Background(), f, scope)
			if err != nil || out.Bound != c.bound {
				t.Fatalf("bound %q, want %q (%v)", out.Bound, c.bound, err)
			}
			encoded, _ := json.Marshal(out)
			if strings.Contains(string(encoded), c.bound) {
				t.Fatal("report-only bound was serialized")
			}
		})
	}
}
