package authorization

import (
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// The existing capture GrantService produces one reviewed parent whose global
// operation union may contain three entries. The inputs/ledger/publication are
// synthetic; this tests the real producer and exact-child C3 methods, not SQL,
// canonical schema validation or actual capture/unwrap authority.
func TestRawSyscallQueryThreeOperationParentProducer(t *testing.T) {
	f := newGrantFixture(t)
	operations := []string{value.GrantSyscallQueryOperation, value.GrantDownloadOperation, value.GrantPacketQueryOperation}
	access := f.access()
	access.ActionIDs = []string{"packet", "syscall"}
	access.Operations = slices.Clone(operations)
	access.MaxArtifacts = 2
	access.MaxBytes = 32 << 20
	access.MaxOperations = 4
	in := f.input(7, access)
	in.DataClass = "raw"
	in.Scope = []byte(`{"schemaVersion":"recorder-preview/v1","actions":[{"actionID":"packet","kind":"packetCapture","profile":"rawPackets"},{"actionID":"syscall","kind":"syscallTrace","mode":"arguments"}]}`)
	in.ExecutionDigest = sha256.Sum256(in.Scope)
	in.Review.Actions = []GrantReviewAction{{ActionID: "packet", Kind: "packetCapture"}, {ActionID: "syscall", Kind: "syscallTrace"}}
	in.Reasons = []value.SensitiveReason{{ActionID: "packet", Code: "rawBytePredicate"}, {ActionID: "syscall", Code: "syscallArguments"}}
	caller := grantIdentity{f.requester, &f.now}
	pending, replay, err := f.svc.Request(t.Context(), caller, in)
	want := []string{value.GrantDownloadOperation, value.GrantPacketQueryOperation, value.GrantSyscallQueryOperation}
	if err != nil || replay || pending.Kind != value.GrantAdHocCapture || pending.DataClass != "raw" || pending.ResultAccess == nil || !slices.Equal(pending.ResultAccess.Operations, want) || len(f.store.rows) != 1 {
		t.Fatal("three-operation raw parent producer", err, replay)
	}
	if !slices.Equal(access.Operations, operations) {
		t.Fatal("producer mutated authored operation order")
	}
	if pending.ResultAccessDigest != ResultAccessDigest(pending.CaptureID, pending.ExecutionDigest, NormalizeResultAccess(*access)) {
		t.Fatal("operation union not digest-bound")
	}
	again, replay, err := f.svc.Request(t.Context(), caller, in)
	if err != nil || !replay || again.ID != pending.ID || again.ReviewDigest != pending.ReviewDigest || len(f.store.rows) != 1 {
		t.Fatal("parent replay changed review", err, replay)
	}
	approved := f.approve(t, pending)
	view, _, err := f.svc.Get(t.Context(), caller, approved.ID)
	if err != nil || view.Phase != value.GrantApproved || !slices.Equal(view.Grant.ResultAccess.Operations, want) || view.Grant.ResultAccessDigest != pending.ResultAccessDigest {
		t.Fatal("actual grant view lost operation union", err)
	}

	f.requester.Scopes = []string{"evidence:read", "evidence:raw", "evidence:download"}
	caller = grantIdentity{f.requester, &f.now}
	_, _, packet := rawPacketProjectionFixture()
	packet.DisplayVersion = query.PacketQueryDisplayVersion
	packet.PacketQuery, _ = (query.PacketQuerySelection{Fields: []query.PacketQueryField{query.PacketIndex}, MaxPackets: 2, MaxScanBytes: 1000}).Window()
	_, _, syscall := newSyscallProjectionFixture(artifact.SyscallArgumentsArtifact, query.SyscallQueryView)
	bind := func(scope *query.ContextProjectionScope, action string, id int) ContextProjectionEvidence {
		scope.RootID, scope.CaptureID, scope.ArtifactID = grantRoot, approved.CaptureID, grantID(id)
		scope.ClusterID, scope.NamespaceUID, scope.WorkloadUID, scope.PodUID = f.target.ClusterID, f.target.NamespaceUID, f.target.WorkloadUID, f.target.PodUID
		scope.Principal, scope.RawGrantID, scope.Version = f.requester.Principal, approved.ID, artifact.Digest{byte(id)}
		record := ContextProjectionEvidence{CaptureID: approved.CaptureID, ActionID: action, ExecutionDigest: approved.ExecutionDigest, Version: scope.Version}
		record.Retained.Input.Target = f.target
		f.store.locator[scope.ArtifactID] = approved.CaptureID
		if !scope.Valid() {
			t.Fatal("invalid exact source fixture", action)
		}
		return record
	}
	packetRecord := bind(&packet, "packet", 500)
	syscallRecord := bind(&syscall, "syscall", 501)
	// Both mismatches start with a fresh child ledger and available pool; they
	// cannot pass merely because a previous successful use spent the allowance.
	if _, _, err = f.svc.SyscallProjectionGrant(t.Context(), caller, packet, packetRecord, true); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("global union widened packet artifact into syscall use", err)
	}
	if _, _, err = f.svc.PacketProjectionGrant(t.Context(), caller, syscall, syscallRecord, true); !errors.Is(err, value.ErrGrantScope) {
		t.Fatal("global union widened syscall artifact into packet use", err)
	}
	if len(f.store.children) != 0 {
		t.Fatal("unsupported source materialized child")
	}
	packetRef, _, err := f.svc.PacketProjectionGrant(t.Context(), caller, packet, packetRecord, true)
	if err != nil || !packetRef.Valid() || packetRef.ParentID != approved.ID {
		t.Fatal("packet exact child", err)
	}
	syscallRef, _, err := f.svc.SyscallProjectionGrant(t.Context(), caller, syscall, syscallRecord, true)
	if err != nil || !syscallRef.Valid() || syscallRef.ParentID != approved.ID || syscallRef.ChildID == packetRef.ChildID {
		t.Fatal("syscall exact child", err)
	}
	stored := f.store.rows[approved.ID]
	if len(f.store.children) != 2 || stored.Spent.Artifacts != 2 || stored.Spent.Bytes != 0 || stored.Spent.Operations != 0 {
		t.Fatal("approval lookup disclosed or replaced pool", stored.Spent)
	}
}

func TestRawSyscallQueryParentProducerRejectsDuplicateAndUnsupportedOperations(t *testing.T) {
	for name, ops := range map[string][]string{
		"duplicate":   {value.GrantDownloadOperation, value.GrantSyscallQueryOperation, value.GrantSyscallQueryOperation},
		"unsupported": {value.GrantDownloadOperation, value.GrantPacketQueryOperation, "future_query"},
		"fourth":      {value.GrantDownloadOperation, value.GrantPacketQueryOperation, value.GrantSyscallQueryOperation, "future_query"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGrantFixture(t)
			access := f.access()
			access.Operations = slices.Clone(ops)
			in := f.input(7, access)
			in.DataClass = "raw"
			g, replay, err := f.svc.Request(t.Context(), grantIdentity{f.requester, &f.now}, in)
			if !errors.Is(err, value.ErrGrantInvalid) || replay || g.ID != "" || len(f.store.rows)+len(f.store.children)+len(f.store.uses) != 0 {
				t.Fatal("invalid operation set reached producer store", err, replay)
			}
			if !slices.Equal(access.Operations, ops) {
				t.Fatal("rejected input mutated")
			}
		})
	}
}
