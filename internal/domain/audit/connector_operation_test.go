package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func connectorAuditIntent() OperationIntent {
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	b := fleet.PeerBinding{InstallationID: "00000000-0000-4000-8000-000000000001", ClusterID: "00000000-0000-4000-8000-000000000002", IssuerEpoch: "00000000-0000-4000-8000-000000000003", PeerID: "00000000-0000-4000-8000-000000000004", Role: fleet.ConnectorPeer}
	return OperationIntent{ID: "00000000-0000-4000-8000-000000000005", RootID: b.InstallationID, TraceID: b.PeerID, Name: "connector_client_certificate", InputFormat: "connector-credential/v1", MACVersion: "mac-v1", AccountVersion: "account-v1", Peer: &OperationPeerActor{Binding: b, CertificateDigest: artifact.Digest{1}}, PrincipalDigest: artifact.Digest{2}, InputDigest: artifact.Digest{3}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Hour)}
}
func TestConnectorOperationUsesExclusivePrivateActor(t *testing.T) {
	valid := connectorAuditIntent()
	if !valid.Valid() {
		t.Fatal("valid private audit facts rejected")
	}
	if OperationLane(valid.Name) != "identity" {
		t.Fatal("private signing used public lane")
	}
	cases := map[string]func(*OperationIntent){
		"fabricated human": func(r *OperationIntent) {
			r.Actor = identity.Principal{Issuer: "https://identity.invalid", Subject: "connector", ClientID: "hub", Kind: identity.Workload}
		},
		"missing peer":           func(r *OperationIntent) { r.Peer = nil },
		"node role":              func(r *OperationIntent) { p := *r.Peer; p.Binding.Role = fleet.NodePeer; r.Peer = &p },
		"public format":          func(r *OperationIntent) { r.InputFormat = "context-input/v1" },
		"public operation":       func(r *OperationIntent) { r.Name = "get_case" },
		"unknown private name":   func(r *OperationIntent) { r.Name = "connector_any_certificate" },
		"unverified certificate": func(r *OperationIntent) { p := *r.Peer; p.CertificateDigest = artifact.Digest{}; r.Peer = &p },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := valid
			change(&r)
			if r.Valid() {
				t.Fatal("invalid actor admitted")
			}
		})
	}
}
func TestConnectorOperationOutcomeCannotImpersonatePublicEvidence(t *testing.T) {
	in := connectorAuditIntent()
	valid := OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", OutputDigest: artifact.Digest{4}, OutputBytes: 1, MetadataUntil: in.RequestUntil, RecordedAt: in.CreatedAt.Add(time.Second), Credential: &OperationCredentialOutcome{OperationID: in.ID, Usage: "client", CertificateDigest: artifact.Digest{5}, NotAfter: in.CreatedAt.Add(30 * time.Minute)}}
	if !valid.Valid() {
		t.Fatal("valid credential facts rejected")
	}
	cases := map[string]func(*OperationOutcome){
		"wrong usage":           func(r *OperationOutcome) { c := *r.Credential; c.Usage = "server"; r.Credential = &c },
		"wrong operation":       func(r *OperationOutcome) { c := *r.Credential; c.OperationID = in.RootID; r.Credential = &c },
		"no result":             func(r *OperationOutcome) { r.Credential = nil },
		"evidence references":   func(r *OperationOutcome) { r.ArtifactIDs = []string{in.ID} },
		"unknown is not signed": func(r *OperationOutcome) { r.Status = "unavailable"; r.Effect = "unknown" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := valid
			change(&r)
			if r.Valid() {
				t.Fatal("invalid outcome accepted")
			}
		})
	}
	uncertain := valid
	uncertain.Status = "unavailable"
	uncertain.Reason = "not_available"
	uncertain.Effect = "unknown"
	uncertain.Credential = nil
	if !uncertain.Valid() {
		t.Fatal("conservative unknown outcome rejected")
	}
}

// This pre-extension shape deliberately retains the old field order and tags.
// It checks bytes, not equivalent decoded JSON, because old record digests bind
// those exact bytes across replay and independent object verification.
func TestConnectorExtensionPreservesHistoricalOperationBytes(t *testing.T) {
	type oldIntent struct {
		ID, RootID, TraceID, Name, InputFormat, MACVersion, AccountVersion string
		Actor                                                              identity.Principal
		PrincipalDigest, InputDigest                                       artifact.Digest
		CreatedAt, RequestUntil, WriteUntil, RetainUntil                   time.Time
		Lifecycle                                                          *OperationLifecycleBinding `json:",omitempty"`
	}
	in := connectorAuditIntent()
	in.Name = "get_capture"
	in.InputFormat = "context-input/v1"
	in.Peer = nil
	in.Actor = identity.Principal{Issuer: "https://identity.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}
	old := oldIntent{in.ID, in.RootID, in.TraceID, in.Name, in.InputFormat, in.MACVersion, in.AccountVersion, in.Actor, in.PrincipalDigest, in.InputDigest, in.CreatedAt, in.RequestUntil, in.WriteUntil, in.RetainUntil, nil}
	want, _ := json.Marshal(old)
	got, _ := json.Marshal(in)
	if !bytes.Equal(got, want) {
		t.Fatalf("legacy bytes changed\n%s\n%s", want, got)
	}
	if !in.Valid() {
		t.Fatal("legacy actor rejected")
	}
	private, _ := json.Marshal(connectorAuditIntent())
	if strings.Contains(string(private), `"Actor"`) {
		t.Fatal("private record contains invented principal")
	}
}

func TestPrivateOperationMaximumFactsRemainWithinExistingRecordLimits(t *testing.T) {
	in := connectorAuditIntent()
	in.MACVersion = strings.Repeat("\\", 64)
	in.AccountVersion = strings.Repeat("\"", 64)
	raw, e := json.Marshal(in)
	if e != nil || !in.Valid() || len(raw) > 8192 {
		t.Fatal("private intent exceeds existing SQL limit", len(raw), e)
	}
	out := OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", OutputDigest: artifact.Digest{255}, OutputBytes: OperationOutputLimit, MetadataUntil: in.RequestUntil, RecordedAt: in.CreatedAt.Add(time.Second), Credential: &OperationCredentialOutcome{OperationID: in.ID, Usage: "client", CertificateDigest: artifact.Digest{255}, NotAfter: in.CreatedAt.Add(30 * time.Minute)}}
	raw, e = json.Marshal(out)
	if e != nil || !out.Valid() || len(raw) > 16384 {
		t.Fatal("private outcome exceeds existing SQL limit", len(raw), e)
	}
	// This tests only bounded record serialization. The private business ledger,
	// lifecycle binding and heap/index/WAL footprint still require49 qualification.
}

func TestConnectorProcessAuditDoesNotInventTLSOrHumanActor(t *testing.T) {
	in := connectorAuditIntent()
	b := in.Peer.Binding
	in.Peer = nil
	in.Name = "connector_process_enrollment"
	in.InputFormat = "connector-process/v1"
	in.Process = &OperationConnectorProcessActor{Process: fleet.ConnectorProcessIdentity{Binding: b, PodUID: b.PeerID, ProcessEpoch: in.ID}, Deployment: fleet.ConnectorDeployment{Namespace: "connector", NamespaceUID: b.InstallationID, ServiceAccount: "connector", AccountUID: b.ClusterID, Deployment: "connector", DeploymentUID: b.PeerID, ServingSlots: 2, RetainedProcesses: 4}, ClientKeyDigest: artifact.Digest{1}, ServerKeyDigest: artifact.Digest{2}}
	if !in.Valid() {
		t.Fatal("explicit initial process actor rejected")
	}
	wire, _ := json.Marshal(in)
	if bytes.Contains(wire, []byte(`"Actor"`)) || bytes.Contains(wire, []byte(`"Peer"`)) {
		t.Fatal("invented identity branch in initial process audit")
	}
	for _, name := range []string{"get_case", "connector_any_certificate"} {
		bad := in
		bad.Name = name
		if bad.Valid() {
			t.Fatal("process actor crossed fixed operation boundary")
		}
	}
	bad := in
	bad.Peer = &OperationPeerActor{Binding: b, CertificateDigest: artifact.Digest{3}}
	if bad.Valid() {
		t.Fatal("mixed TLS and Pod actor")
	}
	cert := in
	cert.Name = "connector_client_certificate"
	cert.InputFormat = "connector-credential/v1"
	if !cert.Valid() {
		t.Fatal("initial certificate lacks its actual Pod actor")
	}
	out := OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", OutputDigest: artifact.Digest{4}, OutputBytes: 1, MetadataUntil: in.RequestUntil, RecordedAt: in.CreatedAt.Add(time.Second)}
	if !out.Valid() {
		t.Fatal("process admission without invented leaf rejected")
	}
	out.Credential = &OperationCredentialOutcome{OperationID: in.ID, Usage: "client", CertificateDigest: artifact.Digest{5}, NotAfter: in.CreatedAt.Add(30 * time.Minute)}
	if out.Valid() {
		t.Fatal("process admission fabricated certificate")
	}
}
