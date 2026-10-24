package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"testing"
	"time"
)

func TestQueryWorkerProofCannotSwapPurposeProcessOrOriginalInterval(t *testing.T) {
	a := testAuthority()
	q, err := NewContextQuery(queryTestID, queryTestID, queryTestID, a, queryPlan(a), a.CheckedAt)
	if err != nil {
		t.Fatal(err)
	}
	w := ContextQueryWorker{QueryID: q.ID, WorkerID: q.WorkerID, PeerID: queryTestID, PodUID: queryTestID, ProcessEpoch: queryTestID, Certificate: artifact.Digest{1}, Configuration: q.Plan.Profile.Path.WorkerConfiguration}
	p := ContextProjectionWorkerProof{Binding: ContextProjectionWorkerBinding{QueryID: q.ID, WorkerID: w.WorkerID, InstallationID: q.Plan.InstallationID, ClusterID: q.Plan.Profile.Path.AcquisitionClusterID, Namespace: "worker", NamespaceUID: "namespace", ServiceAccount: "acquire", ServiceAccountUID: "account", Job: "job", JobUID: "job-uid", Pod: "pod", PodUID: w.PodUID, JobSpec: artifact.Digest{1}, PodSpec: artifact.Digest{2}, Configuration: w.Configuration}, Peer: authorization.KeyPeer{InstallationID: q.Plan.InstallationID, PeerID: w.PeerID, Role: "acquisition", Certificate: w.Certificate, NotBefore: q.CreatedAt, NotAfter: q.CredentialUntil}, ProcessEpoch: w.ProcessEpoch, PublicKey: artifact.Digest{1}, TokenDigest: artifact.Digest{2}, Protection: a.IdentityRevision, ObservedAt: a.CheckedAt, ValidUntil: a.ValidUntil}
	if !p.Matches(q, w, a.CheckedAt) {
		t.Fatal("valid proof rejected")
	}
	for name, mutate := range map[string]func(*ContextProjectionWorkerProof){
		"foreign-query":       func(p *ContextProjectionWorkerProof) { p.Binding.QueryID = queryOtherID },
		"foreign-worker":      func(p *ContextProjectionWorkerProof) { p.Binding.WorkerID = queryOtherID },
		"foreign-cluster":     func(p *ContextProjectionWorkerProof) { p.Binding.ClusterID = queryOtherID },
		"foreign-process":     func(p *ContextProjectionWorkerProof) { p.ProcessEpoch = queryOtherID },
		"foreign-peer":        func(p *ContextProjectionWorkerProof) { p.Peer.PeerID = queryOtherID },
		"foreign-certificate": func(p *ContextProjectionWorkerProof) { p.Peer.Certificate[0]++ },
		"wrong-role":          func(p *ContextProjectionWorkerProof) { p.Peer.Role = "collector" },
		"no-public-key":       func(p *ContextProjectionWorkerProof) { p.PublicKey = artifact.Digest{} },
		"no-token-proof":      func(p *ContextProjectionWorkerProof) { p.TokenDigest = artifact.Digest{} },
		"changed-config":      func(p *ContextProjectionWorkerProof) { p.Binding.Configuration.Generation++ },
		"renewed-certificate": func(p *ContextProjectionWorkerProof) { p.Peer.NotAfter = q.CredentialUntil.Add(time.Second) },
		"renewed-proof": func(p *ContextProjectionWorkerProof) {
			p.ValidUntil = p.ObservedAt.Add(identity.EvidenceReadRequestWindow + 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := p
			mutate(&v)
			if v.Matches(q, w, a.CheckedAt) {
				t.Fatal("changed proof accepted")
			}
		})
	}
	if p.Matches(q, w, p.ValidUntil) {
		t.Fatal("expired proof accepted")
	}
	request := ContextQueryRequest{Call: ContextQueryCall{ID: queryTestID, RootID: q.Scope.RootID, Tool: "get_file_excerpt", InputFormat: "context-query-input/v1", MACVersion: "v1", InputDigest: artifact.Digest{1}, PrincipalDigest: artifact.Digest{2}, Principal: q.Scope.Principal, StartedAt: a.CheckedAt, Until: a.ValidUntil, WriteUntil: a.CheckedAt.Add(30 * time.Second)}, OwnerID: queryTestID, HubProcessEpoch: queryTestID}
	b := ContextProjectionKeyBinding{Purpose: ContextProjectionPurpose, ClaimID: queryTestID, Batch: ContextReadBatch{QueryID: q.ID, ID: queryTestID, OperationID: request.Call.ID, Generation: 1, Worker: w, Request: request, StartedAt: a.CheckedAt, Until: a.ValidUntil, CleanupUntil: q.CleanupUntil}, SourceVersion: q.Scope.Version, Scope: authorization.KeyScope{InstallationID: q.Plan.InstallationID, Purpose: "artifact", KeyID: "context"}, Worker: p, Authority: a, CreatedAt: a.CheckedAt, Until: a.ValidUntil}
	if !b.Valid(q, a.CheckedAt) {
		t.Fatal("valid key binding rejected")
	}
	for name, mutate := range map[string]func(*ContextProjectionKeyBinding){
		"download-purpose": func(b *ContextProjectionKeyBinding) { b.Purpose = "download" },
		"foreign-claim":    func(b *ContextProjectionKeyBinding) { b.ClaimID = queryOtherID },
		"foreign-source":   func(b *ContextProjectionKeyBinding) { b.SourceVersion[0]++ },
		"audit-key":        func(b *ContextProjectionKeyBinding) { b.Scope.Purpose = "audit" },
		"new-owner":        func(b *ContextProjectionKeyBinding) { b.Batch.Request.OwnerID = "" },
		"renewed-interval": func(b *ContextProjectionKeyBinding) { b.Until = b.Until.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			v := b
			mutate(&v)
			if v.Valid(q, a.CheckedAt) {
				t.Fatal("changed key binding accepted")
			}
		})
	}
	if ContextProjectionDataKey.Mask() != 1 || ContextProjectionIndexKey.Mask() != 2 || ContextProjectionManifestKey.Mask() != 4 || ContextProjectionKeyRole("download").Mask() != 0 {
		t.Fatal("ambiguous role mask")
	}
}
