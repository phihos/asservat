package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	configapp "asservat.local/asservat/internal/application/configuration"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

type rawQueryServiceSelection func(context.Context, identities.CurrentIdentity, string, []artifact.Digest) (authapp.RawQuerySelection, error)

func (f rawQueryServiceSelection) ResolveRawQuery(ctx context.Context, current identities.CurrentIdentity, id string, versions []artifact.Digest) (authapp.RawQuerySelection, error) {
	return f(ctx, current, id, versions)
}

// This component composes the real request producer, SQL ledger, service reads
// and public mapper. The exact output/version/length was actually published by
// the context fixture; its raw classification and selection are explicitly
// synthetic. This does not qualify the raw catalog or an installed collector.
func qualifyRawQueryService(t *testing.T, ctx context.Context, s captureAdmissionScenario, store *postgres.AccessGrants, e artifact.ContextExpectation, output value.VerifiedOutput, nativeBytes int64, publishAuthority func() error, releasePermissionBurst func()) {
	t.Helper()
	t.Cleanup(releasePermissionBurst)
	approver := s.batch.Bases[0]
	approver.Resource.UID = custodyID()
	approver.Subjects = []cfg.Subject{{Kind: "Group", Issuer: approver.Subjects[0].Issuer, ID: "raw-service-approvers"}}
	approver.Roles = []string{"action-approver"}
	approver.ScopeDigest = configapp.PermissionScopeDigest(approver)
	batch := s.batch
	batch.Bases = append(slices.Clone(batch.Bases), approver)
	batch.RequestID, batch.InputDigest, batch.Initial = custodyID(), artifact.Digest{7, 4, 9}, nil
	batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	batch.FreshUntil = batch.ObservedAt.Add(5 * time.Second)
	accepted, err := s.p.AcceptPermissions(ctx, batch)
	if err != nil {
		t.Fatal("raw service approver binding", err)
	}
	batch.ExpectedSequence = accepted.Sequence
	for n := 0; n < 2; n++ {
		if err = publishAuthority(); err != nil {
			t.Fatal("raw service permission audit", err)
		}
	}
	as := func(lead bool) identities.CurrentIdentity {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		fresh := batch
		fresh.ObservedAt, fresh.FreshUntil = now, now.Add(5*time.Second)
		if err := s.p.RefreshPermissions(ctx, fresh); err != nil {
			t.Fatal("raw service permissions refresh", err)
		}
		i := s.a.Eligibility.VerifiedIdentity
		i.Principal.Subject = "synthetic-raw-service-dev"
		i.Groups = []string{"maintainers"}
		i.Scopes = []string{"evidence:read", "evidence:download"}
		i.VerifiedAt, i.ValidUntil = now, now.Add(5*time.Second)
		if lead {
			i.Principal.Subject = "synthetic-raw-service-lead"
			i.Groups = []string{"raw-service-approvers"}
			i.Assurance = identity.Assurance{ACR: "gold", AuthenticatedAt: now.Add(-time.Minute), StepUpUntil: now.Add(4 * time.Second)}
		}
		current, _, err := identities.NewBearerRequest(ctx, downloadTestIdentity{i}, "synthetic-reference", time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return current
	}
	selections := 0
	service := authapp.GrantService{RootID: s.a.RootID, InstallationID: s.recovery.installation, Permissions: s.p, Store: store, RawStore: store, Recovery: s.recovery.reader, NewID: custodyID, Now: time.Now}
	service.RawSelections = rawQueryServiceSelection(func(_ context.Context, _ identities.CurrentIdentity, caseID string, versions []artifact.Digest) (authapp.RawQuerySelection, error) {
		selections++
		if caseID != e.CaseID || !slices.Equal(versions, []artifact.Digest{output.ArtifactDigest}) {
			return authapp.RawQuerySelection{}, artifact.ErrInvalid
		}
		return authapp.RawQuerySelection{Artifacts: []value.RawQueryArtifact{{Output: output, NativeBytes: nativeBytes, ExpiresAt: e.Registration.ExpiresAt}}, Review: []authapp.RawQueryReviewArtifact{{Output: output, NativeBytes: nativeBytes, ExpiresAt: e.Registration.ExpiresAt, Namespace: e.Namespace, WorkloadKind: "Deployment", WorkloadName: "synthetic-api", PodName: "synthetic-api-pod", NativeType: artifact.SyscallArgumentsArtifact}}, ValidUntil: time.Now().Add(5 * time.Second)}, nil
	})
	input := authapp.RawQueryRequestInput{CaseID: e.CaseID, ArtifactDigests: []artifact.Digest{output.ArtifactDigest}, Operations: []string{value.GrantDownloadOperation}, Reason: "Inspect the synthetic exact published output", MaxBytes: nativeBytes, Lifetime: 5 * time.Minute, IdempotencyKey: "raw-service-request"}
	pending, replay, err := service.RequestRaw(ctx, as(false), input)
	if err != nil || replay || !pending.Valid() || pending.Phase(time.Now()) != value.GrantPending || !authapp.RawQueryScopeMatches(pending) {
		t.Fatal("service-produced raw request", replay, err)
	}
	originalEnd := pending.RawQuery.NotAfter
	decoded, err := store.Grant(ctx, pending.ID)
	if err != nil || !bytes.Equal(decoded.Scope, pending.Scope) || !bytes.Equal(decoded.Review, pending.Review) || decoded.ExecutionDigest != pending.ExecutionDigest || decoded.ReviewDigest != pending.ReviewDigest {
		t.Fatal("SQL changed producer scope/review", err)
	}
	again, replay, err := service.RequestRaw(ctx, as(false), input)
	if err != nil || !replay || again.ID != pending.ID || selections != 1 || !again.RawQuery.NotAfter.Equal(originalEnd) {
		t.Fatal("service replay reselected or renewed", replay, selections, err)
	}
	changed := input
	changed.Reason += " changed"
	if _, _, err = service.RequestRaw(ctx, as(false), changed); !errors.Is(err, authapp.ErrGrantConflict) {
		t.Fatal("changed request accepted", err)
	}
	if _, _, err = service.Decide(ctx, as(false), pending.ID, true, "self", "raw-service-self"); !errors.Is(err, value.ErrSelfApproval) {
		t.Fatal("service self approval", err)
	}
	approved, replay, err := service.Decide(ctx, as(true), pending.ID, true, "Independent exact artifact review", "raw-service-decision")
	if err != nil || replay || approved.Phase(time.Now()) != value.GrantApproved || approved.Decision == nil || approved.Decision.Approver.Subject != "synthetic-raw-service-lead" || !approved.ExpiresAt.Equal(originalEnd) {
		t.Fatal("service independent decision", replay, err)
	}
	view, until, err := service.Get(ctx, as(true), approved.ID)
	if err != nil || !time.Now().Before(until) || view.Review.RawQuery == nil || len(view.Review.RawQuery.Artifacts) != 1 || view.Review.RawQuery.Artifacts[0].Output != output || view.Review.RawQuery.MaxBytes != nativeBytes {
		t.Fatal("service decoded review", err)
	}
	operations, err := presentation.NewGrantOperations("https://asservat.example.test", time.Now, custodyID, service)
	if err != nil {
		t.Fatal(err)
	}
	readPublic := func() {
		t.Helper()
		args, _ := json.Marshal(map[string]any{"grant_id": approved.ID})
		reply, err := operations.Call(ctx, as(true), "get_grant", args)
		if err != nil {
			t.Fatal("public get_grant rejected service-produced SQL review", err)
		}
		var public struct {
			Status string `json:"status"`
			Data   struct {
				Kind      string            `json:"kind"`
				Reasons   []json.RawMessage `json:"reasons"`
				RawAccess struct {
					CaseID    string `json:"case_id"`
					MaxBytes  int64  `json:"max_bytes"`
					Artifacts []struct {
						ID          string                             `json:"artifact_id"`
						Digest      string                             `json:"digest"`
						Execution   string                             `json:"execution_digest"`
						NativeBytes int64                              `json:"native_bytes"`
						Target      presentation.ContextCaseTargetData `json:"target"`
					} `json:"artifacts"`
				} `json:"raw_access"`
			} `json:"data"`
		}
		if json.Unmarshal(reply.Body, &public) != nil || public.Status != "ok" || public.Data.Kind != value.GrantRawQuery || len(public.Data.Reasons) != 0 || public.Data.RawAccess.CaseID != e.CaseID || public.Data.RawAccess.MaxBytes != nativeBytes || len(public.Data.RawAccess.Artifacts) != 1 {
			t.Fatal("public raw review shape", string(reply.Body))
		}
		a := public.Data.RawAccess.Artifacts[0]
		if a.ID != output.ArtifactID || a.Digest != hex.EncodeToString(output.ArtifactDigest[:]) || a.Execution != hex.EncodeToString(output.ExecutionDigest[:]) || a.NativeBytes != nativeBytes || a.Target.ClusterID != output.Target.ClusterID || a.Target.NamespaceUID != output.Target.NamespaceUID || a.Target.WorkloadUID != output.Target.WorkloadUID || a.Target.PodUID != output.Target.PodUID {
			t.Fatal("public raw review lost exact published tuple")
		}
	}
	readPublic()
	scope := artifact.DownloadScope{RootID: s.a.RootID, Principal: approved.Requester, CaptureID: output.CaptureID, ArtifactID: output.ArtifactID, Version: output.ArtifactDigest, ClusterID: output.Target.ClusterID, NamespaceUID: output.Target.NamespaceUID, WorkloadUID: output.Target.WorkloadUID, PodUID: output.Target.PodUID}
	if until, err := service.CurrentResultAccessForPreparation(ctx, as(false), scope, output.ActionID, &nativeBytes); err != nil || !time.Now().Before(until) {
		t.Fatal("full-file service result access/materialization", err)
	}
	child, err := store.GrantChildFor(ctx, approved.ID, output.ArtifactID, approved.Requester.ClientID)
	if err != nil || child.Output != output || child.ParentID != approved.ID {
		t.Fatal("exact service-materialized child", err)
	}
	useID := custodyID()
	use := value.GrantUse{Operation: value.GrantDownloadOperation, Bytes: nativeBytes, Operations: 1}
	if err = service.ReserveRawResult(ctx, as(false), scope, useID, use); err != nil {
		t.Fatal("service exact file spend", err)
	}
	if err = service.ReserveRawResult(ctx, as(false), scope, useID, use); err != nil {
		t.Fatal("service spend replay", err)
	}
	spent, err := store.Grant(ctx, approved.ID)
	if err != nil || spent.Spent.Bytes != nativeBytes || spent.Spent.Operations != 1 || !bytes.Equal(spent.Review, pending.Review) || !spent.RawQuery.NotAfter.Equal(originalEnd) {
		t.Fatal("service spend refilled or changed review", err)
	}
	if _, err = service.CurrentResultAccessForPreparation(ctx, as(false), scope, output.ActionID, &nativeBytes); !errors.Is(err, value.ErrApprovalRequired) {
		t.Fatal("spent full file still covered", err)
	}
	if _, err = service.CurrentResultAccess(ctx, as(false), scope, output.ActionID); err != nil {
		t.Fatal("charged transfer lost current access", err)
	}
	readPublic()
	t.Log("real RequestRaw producer -> SQL scope/review -> independent service decision -> schema-validated get_grant -> exact child/spend replay passed; raw catalog selection remains synthetic")
}
