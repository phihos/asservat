//go:build cgo && libpcap

package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	wire "asservat.local/asservat/api/v1alpha1"
	"asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/pcap"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	captureapp "asservat.local/asservat/internal/application/capture"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// These are two admitted shapes, not a Cartesian maximum or physical storage
// qualification. Actual libpcap uses only a dead EN10MB handle; no collector.
type policyMetadataShape struct {
	name, expression    string
	audience, retention int
}

func policyMetadataShapes(t *testing.T) []policyMetadataShape {
	t.Helper()
	filters := pcap.NewCompiler()
	expression := policyRawExpression
	// Every candidate must pass the real authoring compiler AND the reviewed
	// prefix-read bound, not just libpcap's instruction ceiling in isolation.
	for count := 1; count <= 80; count++ {
		ports := make([]string, count)
		for i := range ports {
			port := 1000 + i
			if i == 0 {
				port = 80
			}
			ports[i] = fmt.Sprintf("dst port %d", port)
		}
		candidate := "(" + strings.Join(ports, " or ") + ") and (" + policyRawExpression + ")"
		spec := bytes.ReplaceAll(publicPolicySpec(t, authorization.AcceptedPolicyAuthority{ClusterID: custodyID()}), []byte("tcp dst port 80"), []byte(candidate))
		p, err := captureapp.CompilePolicyWithRecorders(spec, planning.ContextRecipeName, planning.RecipeDigest(), policyMetadataCompile(filters))
		if err != nil {
			t.Logf("first compiler-refused next candidate clauses=%d filterBytes=%d", count, len(candidate))
			break
		}
		f, err := filters.CompileFilter(candidate)
		if err != nil || packets.CheckPrefixProgram(f.Program) != nil || p.Recorder == nil {
			t.Fatal("prefix candidate", err)
		}
		expression = candidate
	}
	return []policyMetadataShape{{"audience-retention", policyRawExpression, 32, 64}, {"program", expression, 1, 1}}
}

// Candidate expectation uses the same domain projection as SQL admission. The
// later protected SQL cases must measure the ACTUAL returned/stored expectation.
func policyMetadataExpectation(t testing.TB, a capture.Admission) artifact.ContextExpectation {
	t.Helper()
	in := a.Plan.Input
	r := in.Retention
	target := in.Target
	recording, action, err := planning.RecordingForContext(a.Plan)
	if err != nil {
		t.Fatal(err)
	}
	e := artifact.ContextExpectation{ExecutionClass: target.ExecutionClass, NativeType: artifact.PCAPNGArtifact, Recording: &recording, Registration: a.Registration, CaseID: a.CaseID, OccurrenceID: a.OccurrenceID, PodUID: target.Request.PodUID, Namespace: target.Request.Namespace.Name, NamespaceUID: target.Request.Namespace.UID, WorkloadUID: target.Request.Workload.UID, CollectorVersion: in.Capability.CollectorVersion, CollectorImageDigest: in.Capability.CollectorImageDigest, RecipeDigest: a.Plan.RecipeDigest, PlanDigest: a.Plan.ScopeDigest, CaptureUID: in.CaptureID, ActionID: action, DataClass: "metadata", PurposeRef: r.PurposeRef, Audience: a.Eligibility.DefaultAudience, RequestedAgeSeconds: r.RequestedSeconds, MaximumAgeSeconds: r.MaximumSeconds, DeletionBudgetSeconds: r.DeletionBudgetSeconds, RetentionRules: r.Policies, TriggeredAt: a.Registration.AnchorAt}
	if e.Validate() != nil {
		t.Fatal("candidate expectation invalid")
	}
	return e
}

func TestPolicyMetadataBoundaryShapesOffline(t *testing.T) {
	filters := pcap.NewCompiler()
	q, snapshot := capacityNativeQualification(t, custodyID(), custodyID(), custodyID(), custodyID(), "key-v1")
	policyMetadataProfile(&q, &snapshot)
	pool, err := capacityapp.CompileProtectedPoolPlan(snapshot, snapshot.Pools[0].Resource.Name)
	if err != nil {
		t.Fatal("protected boundary source", err)
	}
	totals, err := capacityapp.CompileQualifiedRootBacking(q, pool)
	if err != nil {
		t.Fatal("protected boundary profile", err)
	}
	t.Logf("offline protected profile records=%d recordRow=%d primaryRecordWAL=%d backupCopies=%d WALCopies=%d; native installer records=4, scoped fixture records=3, no increase", totals.Totals().Records, q.RootBacking.Metadata.RecordRowBytes, q.RootBacking.Metadata.RecordWALBytes, q.RootBacking.Metadata.BackupCopies, q.RootBacking.Metadata.WALCopies)
	for _, shape := range policyMetadataShapes(t) {
		t.Run(shape.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			a := policyRecorderOfflineAdmission(t, now)
			for _, p := range policyMetadataRetention(t, a.Storage.ClusterID, shape.retention-1) {
				a.Plan.Input.Retention.Policies = append(a.Plan.Input.Retention.Policies, artifact.RetentionRule{UID: p.Policy.Revision.UID, Generation: p.Policy.Revision.Generation, Digest: p.Policy.Revision.Digest})
			}
			owner := a.Eligibility.DefaultAudience[0]
			for i := 1; i < shape.audience; i++ {
				next := owner
				next.AssignmentID = custodyID()
				next.SubjectID = policyMetadataText(256, fmt.Sprint(i))
				next.BasisUID = policyMetadataText(64, "basis"+fmt.Sprint(i))
				a.Eligibility.DefaultAudience = append(a.Eligibility.DefaultAudience, next)
			}
			spec := bytes.ReplaceAll(publicPolicySpec(t, authorization.AcceptedPolicyAuthority{ClusterID: a.Storage.ClusterID}), []byte("tcp dst port 80"), []byte(shape.expression))
			compiled, err := captureapp.CompilePolicyWithRecorders(spec, planning.ContextRecipeName, planning.RecipeDigest(), policyMetadataCompile(filters))
			if err != nil || compiled.Recorder == nil {
				t.Fatal("real compiler shape", err)
			}
			a, p := buildPolicyRecorderAdmissionFixture(t, a, compiled.Recorder.Composition, filters, now)
			requirePolicyRecorderAdmissionFixture(t, a, p, now)
			e := policyMetadataExpectation(t, a)
			// Largest common issuer under the ACTUAL 64KiB expectation envelope. This
			// is a combined bound; 32 independently maximal issuers do not fit.
			low, high := 1, 2048
			for low < high {
				n := (low + high + 1) / 2
				for i := range e.Audience {
					e.Audience[i].Issuer = "https://id.example.test/" + policyMetadataText(max(0, n-24), "issuer")
				}
				b, _ := json.Marshal(e)
				if len(b) <= 65536 {
					low = n
				} else {
					high = n - 1
				}
			}
			for i := range e.Audience {
				e.Audience[i].Issuer = "https://id.example.test/" + policyMetadataText(max(0, low-24), "issuer")
			}
			b, err := json.Marshal(e)
			if err != nil || len(b) > 65536 || e.Validate() != nil {
				t.Fatal("combined expectation shape", len(b), err)
			}
			program, _ := json.Marshal(e.Recording.Filter.Program)
			identity, _ := json.Marshal(a.Eligibility.VerifiedIdentity)
			t.Logf("compiler=%q shape=%s scope=%d expectation=%d identity=%d programJSON=%d instructions=%d filterBytes=%d audience=%d issuerBytes=%d retention=%d; candidate-only, no SQL/native/physical proof", filters.Version(), shape.name, len(a.Plan.CanonicalScope), len(b), len(identity), len(program), len(e.Recording.Filter.Program), len(shape.expression), len(e.Audience), len(e.Audience[0].Issuer), len(e.RetentionRules))
		})
	}
}

func policyMetadataText(n int, seed string) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		digest := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", seed, i)))
		b.WriteString(hex.EncodeToString(digest[:]))
	}
	return b.String()[:n]
}

// The published decoder validates the real spec and computes its canonical
// definition digest. Unique source IDs are distinct from shared definitions.
func policyMetadataRetention(t testing.TB, cluster string, count int) []privacy.ScopedPolicy {
	t.Helper()
	decoder, err := kubernetes.NewRetentionPolicySpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	out := make([]privacy.ScopedPolicy, 0, count)
	for i := 1; i <= count; i++ {
		spec := wire.RetentionPolicySpec{Scope: wire.RetentionScope{ClusterIDs: []string{cluster}}, PurposeRef: "diagnostics", Defaults: wire.RetentionDurations{EvidenceSeconds: 3600, CaseMetadataSeconds: 3600, AuditMetadataSeconds: 3600}, Maxima: wire.RetentionDurations{EvidenceSeconds: 86400 - int64(min(i, 59)), CaseMetadataSeconds: 86400, AuditMetadataSeconds: 86400}, Rules: []wire.RetentionRule{}, DeletionBudgetSeconds: 1, LegalExceptions: "disabled"}
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		p, err := decoder.DecodeRetentionPolicySpec(raw, true)
		if err != nil {
			t.Fatal("legal retention boundary spec", err)
		}
		p.Name = policyMetadataText(63, fmt.Sprint(i))
		p.Policy.Revision.UID = policyMetadataText(64, fmt.Sprint(i))
		p.Policy.Revision.Generation = 2147483647
		if !p.Policy.Valid() || !p.Scope.Valid() || p.Policy.Baseline {
			t.Fatal("invalid scoped retention definition")
		}
		out = append(out, p)
	}
	return out
}

func TestPolicyMetadataRetentionListUsesSourceUID(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	cluster := custodyID()
	snapshot := privacy.PolicySnapshot{SourceClusterID: cluster, ControlNamespaceUID: custodyID(), Hub: true, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Policies: append([]privacy.ScopedPolicy{retentionEffectDefaultPolicy()}, policyMetadataRetention(t, cluster, 63)...)}
	snapshot.Revision = identity.Revision{UID: snapshot.ControlNamespaceUID, Generation: 1, Digest: configapp.RetentionSnapshotDigest(snapshot)}
	if !snapshot.Valid(now) {
		t.Fatal("retention input invalid before journal")
	}
	if _, err := configapp.NewRetentionJournal(retentionFixturePolicyList(snapshot), now); err != nil {
		t.Fatal("actual fixture list rejected by real journal", err)
	}
}
