package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestContextPlanRequiresExactFiniteNativeControlBacking(t *testing.T) {
	const root = "10000000-0000-4000-8000-000000000001"
	const allocation = "10000000-0000-4000-8000-000000000002"
	const installation = "10000000-0000-4000-8000-000000000003"
	const store = "10000000-0000-4000-8000-000000000004"
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := now.Add(time.Hour)
	a := artifact.DownloadAllocation{ID: allocation, RootID: root, ClusterID: installation, NamespaceUID: "ns", WorkloadUID: "workload", OutputLimit: 16384, ReadLimit: 32 << 20, ValidUntil: until}
	c := custodydb.DownloadControlAllocation{ID: id(allocation), RootID: id(root), AuditStoreID: id(store), WindowLimit: 2, AuditByteLimit: 4 * artifact.DownloadWindowAuditBytes, ValidUntil: ts(until), AuditWriteUntil: ts(until.Add(time.Minute))}
	native := authorization.NativeBacking{AllocationID: allocation, RootID: root, PolicyID: store, PolicyDigest: artifact.Digest{1}, Rows: 2, Keys: 2, TransitionsPerRow: 8, BackupBytes: 32 << 20, WALBytes: 64 << 20, CleanupSeconds: 30, ValidUntil: until, RetireBy: until.Add(30 * time.Second), History: authorization.NativeHistoryQualification{ID: installation, Digest: artifact.Digest{2}, RowBytes: 64 << 10, TransitionWALBytes: 64 << 10, BackupCopies: 1, WALCopies: 1}}
	wire, _ := json.Marshal(native)
	n := custodydb.DownloadNativeBacking{AllocationID: id(allocation), RootID: id(root), PolicyJson: wire, RowsLimit: 2, KeysLimit: 2, TransitionsPerRow: 8, CleanupSeconds: 30, ValidUntil: ts(until), RetireBy: ts(native.RetireBy)}
	typ, _ := artifact.LookupNativeType(artifact.PodStatusArtifact)
	limits := ContextDownloadPlanLimits{OutputLimit: 8192, ReadLimit: 8 << 20}
	if !contextPlanBacking(limits, typ, a, c, n, now) {
		t.Fatal("exact supported backing rejected")
	}
	for _, change := range []func(*custodydb.DownloadControlAllocation, *custodydb.DownloadNativeBacking){
		func(c *custodydb.DownloadControlAllocation, _ *custodydb.DownloadNativeBacking) {
			c.ReservedWindows = c.WindowLimit
		},
		func(c *custodydb.DownloadControlAllocation, _ *custodydb.DownloadNativeBacking) {
			c.ReservedAuditBytes = c.AuditByteLimit
		},
		func(_ *custodydb.DownloadControlAllocation, n *custodydb.DownloadNativeBacking) {
			n.Overdue = true
		},
		func(_ *custodydb.DownloadControlAllocation, n *custodydb.DownloadNativeBacking) {
			n.ChargedKeys = n.KeysLimit
		},
		func(_ *custodydb.DownloadControlAllocation, n *custodydb.DownloadNativeBacking) {
			n.TransitionsPerRow = 7
		},
	} {
		cc, nn := c, n
		change(&cc, &nn)
		if contextPlanBacking(limits, typ, a, cc, nn, now) {
			t.Fatal("unsupported or exhausted backing accepted")
		}
	}
	if contextPlanBacking(limits, typ, a, c, n, until) {
		t.Fatal("expired original backing accepted")
	}
	// An old eight-record workload has enough aggregate byte funding for a
	// default 16 MiB profile, but its ten owner updates cannot fund renewals.
	for _, name := range []string{artifact.PprofArtifact, artifact.GoTraceArtifact} {
		typ, _ := artifact.LookupNativeType(name)
		profileLimits, err := boundedNativeDownloadPlan(ContextDownloadPlanLimits{OutputLimit: artifact.ProfileDownloadOutputBytes, ReadLimit: artifact.ProfileDownloadReadBytes}, typ, 16<<20)
		if err != nil {
			t.Fatal(err)
		}
		legacyAllocation := a
		legacyAllocation.OutputLimit, legacyAllocation.ReadLimit = 8*(16<<20), 8*(24<<20)
		for _, allowance := range []int64{10, artifact.ProfileDownloadNativeTransitions - 1, artifact.ProfileDownloadNativeTransitions} {
			old := native
			old.TransitionsPerRow = allowance
			legacy := n
			legacy.TransitionsPerRow = allowance
			legacy.PolicyJson, _ = json.Marshal(old)
			want := allowance == artifact.ProfileDownloadNativeTransitions
			if got := contextPlanBacking(profileLimits, typ, legacyAllocation, c, legacy, now); got != want {
				t.Fatalf("profile %s owner allowance %d admission=%v want=%v", name, allowance, got, want)
			}
		}
	}
	// Profile funding needs both windows and their independent key/audit slots.
	typ, _ = artifact.LookupNativeType(artifact.GoTraceArtifact)
	limits.OutputLimit, limits.ReadLimit = artifact.ProfileDownloadOutputBytes, artifact.ProfileDownloadReadBytes
	a.OutputLimit, a.ReadLimit = limits.OutputLimit, limits.ReadLimit
	native.TransitionsPerRow, n.TransitionsPerRow = artifact.ProfileDownloadNativeTransitions, artifact.ProfileDownloadNativeTransitions
	n.PolicyJson, _ = json.Marshal(native)
	if !contextPlanBacking(limits, typ, a, c, n, now) {
		t.Fatal("two-window funding refused")
	}
	cc := c
	cc.ReservedWindows = 1
	if contextPlanBacking(limits, typ, a, cc, n, now) {
		t.Fatal("one remaining window funded two-window response")
	}
	cc = c
	cc.ReservedAuditBytes = artifact.DownloadWindowAuditBytes
	if contextPlanBacking(limits, typ, a, cc, n, now) {
		t.Fatal("missing window audit funded")
	}
	nn := n
	nn.ChargedKeys = 1
	if contextPlanBacking(limits, typ, a, c, nn, now) {
		t.Fatal("one remaining key funded two-window response")
	}
	native.TransitionsPerRow, n.TransitionsPerRow = 8, 8
	n.PolicyJson, _ = json.Marshal(native)
	if contextPlanBacking(limits, typ, a, c, n, now) {
		t.Fatal("insufficient transitions funded")
	}
}

func TestNativeDownloadPlanUsesAcceptedTypeAndSize(t *testing.T) {
	ceilings := ContextDownloadPlanLimits{OutputLimit: artifact.ProfileDownloadOutputBytes, ReadLimit: artifact.ProfileDownloadReadBytes}
	for _, name := range []string{artifact.PodStatusArtifact, artifact.PCAPNGArtifact, artifact.RawPCAPNGArtifact, artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact, artifact.HTTPHeadersArtifact, artifact.LogsArtifact, artifact.PprofArtifact, artifact.GoTraceArtifact} {
		typ, _ := artifact.LookupNativeType(name)
		for _, size := range []int64{1, min(typ.MaxBytes, 16<<20), typ.MaxBytes} {
			got, err := boundedNativeDownloadPlan(ceilings, typ, size)
			if err != nil || !got.valid() {
				t.Fatal(name, size, got, err)
			}
			if name != artifact.LogsArtifact && name != artifact.PprofArtifact && name != artifact.GoTraceArtifact {
				if got.OutputLimit != 16<<20 || got.ReadLimit != 24<<20 {
					t.Fatal("small source inflated to profile reservation", got)
				}
			} else {
				if got.OutputLimit != max(artifact.MaxContextBytes, 2*size) || got.ReadLimit > ceilings.ReadLimit || got.ReadLimit < artifact.ProfileDownloadWindowReadWork {
					t.Fatal("profile budget", got)
				}
			}
		}
		if _, err := boundedNativeDownloadPlan(ceilings, typ, typ.MaxBytes+1); err == nil {
			t.Fatal("unsupported native limit")
		}
	}
	typ, _ := artifact.LookupNativeType(artifact.GoTraceArtifact)
	old := ceilings
	old.ReadLimit = 24 << 20
	if _, err := boundedNativeDownloadPlan(old, typ, artifact.MaxGoTraceBytes); err == nil {
		t.Fatal("old installation ceiling silently enlarged")
	}
}

// Compose the actual bounded plan, audited metadata accounting and domain
// response admission. Authority facts are synthetic; this does not read or
// decrypt managed evidence or qualify an installed native transfer.
func TestNativeDownloadPlanFundsResponseAfterMetadata(t *testing.T) {
	ceilings := ContextDownloadPlanLimits{OutputLimit: artifact.ProfileDownloadOutputBytes, ReadLimit: artifact.ProfileDownloadReadBytes}
	for _, name := range []string{artifact.LogsArtifact, artifact.PprofArtifact, artifact.GoTraceArtifact} {
		typ, ok := artifact.LookupNativeType(name)
		if !ok {
			t.Fatal("registered native type missing", name)
		}
		for _, size := range []int64{1, 1 << 20, typ.MaxBytes} {
			t.Run(fmt.Sprintf("%s/%d", name, size), func(t *testing.T) {
				plan, err := boundedNativeDownloadPlan(ceilings, typ, size)
				if err != nil {
					t.Fatal("accepted native plan", err)
				}
				now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
				const id = "10000000-0000-4000-8000-000000000001"
				authority := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}}, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{2}, DecisionDigest: artifact.Digest{3}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: artifact.Digest{4}}, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), AccessUntil: now.Add(time.Hour)}
				session := artifact.DownloadSession{ID: id, AllocationID: id, Scope: authority.Scope, RequestDigest: artifact.Digest{5}, State: artifact.DownloadPreparing, CreatedAt: now, Deadline: now.Add(time.Hour), OutputLimit: plan.OutputLimit, ReadLimit: plan.ReadLimit}
				session, err = session.Start(authority, artifact.DownloadBatch{ID: id, Purpose: artifact.DownloadMetadata, ReadBytes: evidence.ContextDownloadReadWork}, now)
				if err != nil {
					t.Fatal("original metadata admission", err)
				}
				session.Active.AuditAcknowledged = true
				session, err = session.Finish(id, 1, 0, true, false, now)
				if err != nil || session.State != artifact.DownloadReady || session.ChargedRead != evidence.ContextDownloadReadWork || session.ChargedOutput != 0 {
					t.Fatal("original metadata charge/readiness", session, err)
				}
				response := artifact.DownloadResponse{ID: id, SessionID: id, OwnerID: id, Plan: artifact.DownloadResponsePlan{Version: artifact.DownloadResponseVersion, Selection: artifact.DownloadSelection{Length: size}, WholeFile: true, WindowReadLimit: evidence.NativeWindowReadWork(typ)}, Until: session.Deadline}
				after, admitted, err := session.BeginResponse(authority, response, now)
				if err != nil || !admitted.Valid() || after.Generation != 2 || after.ChargedRead != session.ChargedRead || after.Deadline != session.Deadline || after.ReadLimit != plan.ReadLimit {
					t.Fatalf("bounded native plan cannot fund first response after metadata: remaining=%d response=%d error=%v", session.ReadLimit-session.ChargedRead, response.Plan.ReadBytes(), err)
				}
				windows := (size-1)/artifact.DownloadWindowBytes + 1
				wantReads := evidence.ContextDownloadReadWork + 2*windows*evidence.NativeWindowReadWork(typ)
				if plan.ReadLimit != wantReads || plan.OutputLimit != max(artifact.MaxContextBytes, 2*size) {
					t.Fatal("native plan lost exact original bounds", plan)
				}
				for _, ceiling := range []ContextDownloadPlanLimits{
					{OutputLimit: plan.OutputLimit - 1, ReadLimit: ceilings.ReadLimit},
					{OutputLimit: ceilings.OutputLimit, ReadLimit: wantReads - 1},
				} {
					if _, err := boundedNativeDownloadPlan(ceiling, typ, size); err == nil {
						t.Fatal("administrator ceiling silently increased", ceiling)
					}
				}
			})
		}
	}
}
