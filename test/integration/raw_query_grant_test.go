package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// Component ledger proof using an actually published synthetic context artifact.
// This does not qualify the separate raw entitlement service or native arguments.
func qualifyRawQueryGrants(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, e artifact.ContextExpectation, version artifact.Digest, nativeBytes int64) {
	t.Helper()
	var lane string
	var good, bad bool
	if err := admin.QueryRow(ctx, `SELECT operation_audit_lane('request_raw_access'),operation_audit_human_input_valid('request_raw_access','context-input/v1'),operation_audit_human_input_valid('request_raw_access','context-query-input/v1')`).Scan(&lane, &good, &bad); err != nil || lane != "normal" || !good || bad {
		t.Fatal("raw request audit registration", lane, good, bad, err)
	}
	role := narrowRole(t, ctx, admin, "raw_grant_hub_", "synthetic-raw-grant", func(role string) []string {
		sql, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("missing hub grants")
		}
		return sql
	})
	pool := poolFor(role, "synthetic-raw-grant")
	t.Cleanup(pool.Close)
	store, err := postgres.NewAccessGrants(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	proof := func() artifact.RecoveryProof {
		t.Helper()
		r, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	actor := s.a.Eligibility.VerifiedIdentity.Principal
	output := value.VerifiedOutput{CaptureID: e.CaptureUID, ActionID: e.ActionID, ArtifactID: e.Registration.Location.ArtifactID, ExecutionDigest: e.PlanDigest, ArtifactDigest: version, Target: value.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}}
	makeRequest := func(key string, maxBytes int64) app.StoredGrantRequest {
		now := time.Now().UTC().Truncate(time.Microsecond)
		raw := value.RawQueryScope{CaseID: e.CaseID, Artifacts: []value.RawQueryArtifact{{Output: output, NativeBytes: nativeBytes, ExpiresAt: e.Registration.ExpiresAt}}, Operations: []string{value.GrantDownloadOperation}, Reason: "Inspect saved synthetic evidence", MaxBytes: maxBytes, MaxOperations: 2, NotAfter: now.Add(5 * time.Minute)}
		g := value.Grant{ID: custodyID(), RootID: s.a.RootID, Kind: value.GrantRawQuery, RawQuery: &raw, DataClass: "raw", Requester: actor, Lifetime: 5 * time.Minute, Revision: 1, Reasons: []value.SensitiveReason{{ActionID: "download_artifact", Code: "rawDisclosure"}}}
		g.Scope, g.ExecutionDigest = app.RawQueryScopeBytes(raw)
		g.Review = []byte(`{"synthetic":"exact published artifact"}`)
		g.ReviewDigest = app.ReviewDigest(g, g.Review)
		return app.StoredGrantRequest{Grant: g, IdempotencyKey: key, RequestDigest: artifact.Digest{7, byte(len(key))}}
	}
	in := makeRequest("raw-request", nativeBytes*2)
	type requestResult struct {
		g      value.Grant
		replay bool
		err    error
	}
	requested := make(chan requestResult, 4)
	var wg sync.WaitGroup
	r := proof()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			attempt := in
			attempt.Grant.ID = custodyID()
			g, replay, err := store.RequestGrant(ctx, attempt, r)
			requested <- requestResult{g, replay, err}
		}()
	}
	wg.Wait()
	close(requested)
	var pending value.Grant
	fresh := 0
	for result := range requested {
		if result.err != nil {
			t.Fatal("concurrent request", result.err)
		}
		if !result.replay {
			fresh++
		}
		if pending.ID != "" && pending.ID != result.g.ID {
			t.Fatal("duplicate original request")
		}
		pending = result.g
	}
	if fresh != 1 {
		t.Fatal("original request count", fresh)
	}
	var nullTarget bool
	if err = admin.QueryRow(ctx, `SELECT preview_id IS NULL AND capture_id IS NULL AND cluster_id IS NULL AND namespace_uid IS NULL AND workload_uid IS NULL AND pod_uid IS NULL FROM access_grant WHERE id=$1`, pending.ID).Scan(&nullTarget); err != nil || !nullTarget {
		t.Fatal("fabricated common target", err)
	}
	old, err := store.RawQueryRequest(ctx, actor, in.IdempotencyKey)
	if err != nil || old.Grant.ID != pending.ID || old.RequestDigest != in.RequestDigest || !old.Grant.RawQuery.NotAfter.Equal(in.Grant.RawQuery.NotAfter) {
		t.Fatal("original request lookup", err)
	}
	changed := in
	changed.RequestDigest[0]++
	if _, _, err = store.RequestGrant(ctx, changed, proof()); !errors.Is(err, app.ErrGrantConflict) {
		t.Fatal("changed input replay", err)
	}
	lead := actor
	lead.Subject += "-independent-reviewer"
	approve := func(g value.Grant) value.Grant {
		t.Helper()
		approved, _, err := store.DecideGrant(ctx, app.GrantDecisionInput{GrantID: g.ID, Approve: true, Approver: lead, Reason: "exact files reviewed", ACR: "synthetic-step-up", AuthTime: time.Now().Add(-time.Minute), IdempotencyKey: "approve"}, proof())
		if err != nil {
			t.Fatal("approve", err)
		}
		return approved
	}
	if _, _, err = store.DecideGrant(ctx, app.GrantDecisionInput{GrantID: pending.ID, Approve: true, Approver: actor, Reason: "self", ACR: "synthetic", AuthTime: time.Now(), IdempotencyKey: "self"}, proof()); !errors.Is(err, value.ErrSelfApproval) {
		t.Fatal("self approval", err)
	}
	approved := approve(pending)
	child, _, err := store.MaterializeGrantChild(ctx, app.GrantChildRequest{ChildID: custodyID(), ParentID: approved.ID, ClientID: actor.ClientID, Output: output}, proof())
	if err != nil || child.Output != output {
		t.Fatal("exact published child", err)
	}
	again, replay, err := store.MaterializeGrantChild(ctx, app.GrantChildRequest{ChildID: custodyID(), ParentID: approved.ID, ClientID: actor.ClientID, Output: output}, proof())
	if err != nil || !replay || again.ID != child.ID {
		t.Fatal("child replay", err)
	}
	// Legacy result capacity is shared across reviewed clients. The lookup
	// counts only selected artifact IDs, once, using the compiled hub role.
	legacyScope := []byte(`{"synthetic":"legacy selected artifact capacity"}`)
	legacy := value.Grant{ID: custodyID(), RootID: s.a.RootID, Kind: value.GrantAdHocCapture, PreviewID: custodyID(), CaptureID: output.CaptureID, Target: output.Target, ExecutionDigest: sha256.Sum256(legacyScope), Scope: legacyScope, DataClass: "raw", Requester: actor, Lifetime: 5 * time.Minute, Revision: 1, Reasons: []value.SensitiveReason{{ActionID: output.ActionID, Code: "rawDisclosure"}}, Review: []byte(`{"synthetic":"legacy result selection"}`)}
	legacy.ResultAccess = &value.ResultAccess{ActionIDs: []string{output.ActionID}, Operations: []string{value.GrantDownloadOperation}, ClientIDs: []string{actor.ClientID, "synthetic-other-client"}, MaxArtifacts: 1, MaxBytes: nativeBytes * 2, MaxOperations: 2, NotAfter: time.Now().Add(5 * time.Minute).UTC().Truncate(time.Microsecond)}
	normalizedAccess := app.NormalizeResultAccess(*legacy.ResultAccess)
	legacy.ResultAccess = &normalizedAccess
	legacy.ResultAccessDigest = app.ResultAccessDigest(legacy.CaptureID, legacy.ExecutionDigest, *legacy.ResultAccess)
	legacy.ReviewDigest = app.ReviewDigest(legacy, legacy.Review)
	legacy, _, err = store.RequestGrant(ctx, app.StoredGrantRequest{Grant: legacy, IdempotencyKey: "legacy-selection-capacity", RequestDigest: artifact.Digest{9, 1}}, proof())
	if err != nil {
		t.Fatal("legacy capacity request", err)
	}
	legacy = approve(legacy)
	legacyOutput := output
	legacyOutput.ExecutionDigest = legacy.ExecutionDigest
	for _, client := range legacy.ResultAccess.ClientIDs {
		if _, _, err = store.MaterializeGrantChild(ctx, app.GrantChildRequest{ChildID: custodyID(), ParentID: legacy.ID, ClientID: client, Output: legacyOutput}, proof()); err != nil {
			t.Fatal("legacy client child", err)
		}
	}
	fullSelection := []string{output.ArtifactID}
	for len(fullSelection) < value.GrantMaxResultArtifacts {
		fullSelection = append(fullSelection, custodyID())
	}
	for _, selected := range [][]string{{output.ArtifactID}, {output.ArtifactID, custodyID()}, fullSelection} {
		if count, e := store.CountRegisteredGrantArtifacts(ctx, legacy.ID, selected); e != nil || count != 1 {
			t.Fatal("distinct selected registration across reviewed clients", count, e)
		}
	}
	if count, e := store.CountRegisteredGrantArtifacts(ctx, legacy.ID, []string{custodyID()}); e != nil || count != 0 {
		t.Fatal("unselected registered artifact counted", count, e)
	}
	if count, e := store.CountRegisteredGrantArtifacts(ctx, approved.ID, []string{output.ArtifactID}); e != nil || count != 0 {
		t.Fatal("nonlegacy parent counted", count, e)
	}
	tooMany := make([]string, 65)
	for n := range tooMany {
		tooMany[n] = custodyID()
	}
	for _, invalid := range [][]string{nil, {output.ArtifactID, output.ArtifactID}, tooMany} {
		if _, e := store.CountRegisteredGrantArtifacts(ctx, legacy.ID, invalid); !errors.Is(e, value.ErrGrantInvalid) {
			t.Fatal("unbounded or duplicate selection accepted", e)
		}
	}
	for _, alter := range []string{"capture", "action", "version", "client"} {
		bad := output
		client := actor.ClientID
		switch alter {
		case "capture":
			bad.CaptureID = custodyID()
		case "action":
			bad.ActionID = "unreviewed"
		case "version":
			bad.ArtifactDigest[0]++
		case "client":
			client += "other"
		}
		// Exercise the SQL member guard directly, independently of the Go check.
		if _, err = pool.Exec(ctx, `INSERT INTO access_grant_child(id,root_id,parent_id,capture_id,action_id,artifact_id,artifact_digest,client_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, custodyID(), s.a.RootID, approved.ID, bad.CaptureID, bad.ActionID, bad.ArtifactID, bad.ArtifactDigest[:], client); err == nil {
			t.Fatal("SQL child guard", alter)
		}
	}
	scope := artifact.DownloadScope{RootID: s.a.RootID, Principal: actor, CaptureID: output.CaptureID, ArtifactID: output.ArtifactID, Version: version, ClusterID: output.Target.ClusterID, NamespaceUID: output.Target.NamespaceUID, WorkloadUID: output.Target.WorkloadUID, PodUID: output.Target.PodUID}
	candidates, err := store.RawQueryCandidates(ctx, scope, value.GrantUse{})
	if err != nil || len(candidates) != 1 || candidates[0].ID != approved.ID {
		t.Fatal("current exact candidate", len(candidates), err)
	}
	wrong := scope
	wrong.Principal.ClientID += "other"
	if _, err = store.RawQueryCandidates(ctx, wrong, value.GrantUse{}); !errors.Is(err, app.ErrGrantNotFound) {
		t.Fatal("other client candidate", err)
	}
	// JSONB containment ignores array order; digest equality must not.
	wrongVersion := scope
	for i := 1; i < len(wrongVersion.Version); i++ {
		if wrongVersion.Version[0] != wrongVersion.Version[i] {
			wrongVersion.Version[0], wrongVersion.Version[i] = wrongVersion.Version[i], wrongVersion.Version[0]
			break
		}
	}
	if wrongVersion.Version == scope.Version {
		t.Fatal("synthetic digest did not vary")
	}
	if _, err = store.RawQueryCandidates(ctx, wrongVersion, value.GrantUse{}); !errors.Is(err, app.ErrGrantNotFound) {
		t.Fatal("reordered ciphertext digest selected", err)
	}
	type useResult struct {
		in  app.GrantUseRequest
		err error
	}
	uses := make(chan useResult, 6)
	r = proof()
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			use := app.GrantUseRequest{UseID: custodyID(), ParentID: approved.ID, ChildID: child.ID, Use: value.GrantUse{Operation: value.GrantDownloadOperation, Bytes: nativeBytes, Operations: 1}}
			_, _, err := store.ReserveGrantUse(ctx, use, r)
			uses <- useResult{use, err}
		}()
	}
	wg.Wait()
	close(uses)
	var previous app.GrantUseRequest
	won := 0
	for result := range uses {
		if result.err == nil {
			won++
			previous = result.in
		} else if !errors.Is(result.err, value.ErrGrantPoolExhausted) {
			t.Fatal("concurrent spend", result.err)
		}
	}
	if won != 2 {
		t.Fatal("pool cap", won)
	}
	spent, err := store.Grant(ctx, approved.ID)
	if err != nil || spent.Spent.Bytes != 2*nativeBytes || spent.Spent.Operations != 2 || spent.Spent.Artifacts != 1 {
		t.Fatal("exact nonrefundable pool", spent.Spent, err)
	}
	newerIn := makeRequest("new-raw-request", artifact.MaxNativeBytes)
	// Raw-only review supports the documented 64-artifact presentation bound.
	newerIn.Grant.Review = []byte(`{"synthetic":"` + strings.Repeat("x", 40000) + `"}`)
	newerIn.Grant.ReviewDigest = app.ReviewDigest(newerIn.Grant, newerIn.Grant.Review)
	newer, _, err := store.RequestGrant(ctx, newerIn, proof())
	if err != nil {
		t.Fatal("1TiB raw ceiling", err)
	}
	newer = approve(newer)
	candidates, err = store.RawQueryCandidates(ctx, scope, value.GrantUse{Operation: value.GrantDownloadOperation, Bytes: 1, Operations: 1})
	if err != nil || len(candidates) != 1 || candidates[0].ID != newer.ID {
		t.Fatal("exhausted older grant shadowed covering approval", err)
	}
	originalUse, err := store.GrantUseByID(ctx, previous.UseID)
	if err != nil || originalUse != previous {
		t.Fatal("new approval rehomed prior use", err)
	}
	if after, replay, err := store.ReserveGrantUse(ctx, previous, proof()); err != nil || !replay || after.Spent != spent.Spent {
		t.Fatal("uncertain retry charged again", err)
	}
	for _, sql := range []string{`UPDATE access_grant SET raw_query=jsonb_set(raw_query,'{MaxBytes}','1') WHERE id=$1`, `UPDATE access_grant SET bytes_spent=0 WHERE id=$1`, `UPDATE access_grant SET scope=scope || '\x20'::bytea WHERE id=$1`} {
		if _, err = admin.Exec(ctx, sql, approved.ID); err == nil {
			t.Fatal("raw grant changed", sql)
		}
	}
	// Revocation never rehomes a known use to the newer covering approval.
	if _, _, err = store.RevokeGrant(ctx, app.GrantRevocationInput{GrantID: approved.ID, Revoker: actor, ExpectedRevision: 2, IdempotencyKey: "revoke"}, proof()); err != nil {
		t.Fatal(err)
	}
	originalUse, err = store.GrantUseByID(ctx, previous.UseID)
	if err != nil || originalUse.ParentID != approved.ID {
		t.Fatal("revoked use lost original parent", err)
	}
	expiringIn := makeRequest("expiring-raw-request", nativeBytes)
	expiringIn.Grant.RawQuery.NotAfter = time.Now().UTC().Truncate(time.Microsecond).Add(time.Second)
	expiringIn.Grant.Scope, expiringIn.Grant.ExecutionDigest = app.RawQueryScopeBytes(*expiringIn.Grant.RawQuery)
	expiringIn.Grant.ReviewDigest = app.ReviewDigest(expiringIn.Grant, expiringIn.Grant.Review)
	expiring, _, err := store.RequestGrant(ctx, expiringIn, proof())
	if err != nil {
		t.Fatal("finite expiring request", err)
	}
	timer := time.NewTimer(time.Until(expiring.RawQuery.NotAfter))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	if _, _, err = store.DecideGrant(ctx, app.GrantDecisionInput{GrantID: expiring.ID, Approve: true, Approver: lead, Reason: "late", ACR: "synthetic", AuthTime: time.Now().Add(-time.Minute), IdempotencyKey: "late"}, proof()); !errors.Is(err, value.ErrGrantNotPending) {
		t.Fatal("late raw approval", err)
	}
	// Historical request lookup/replay retains the old end after expiration.
	expiredReplay, wasReplay, err := store.RequestGrant(ctx, expiringIn, proof())
	if err != nil || !wasReplay || !expiredReplay.RawQuery.NotAfter.Equal(expiring.RawQuery.NotAfter) {
		t.Fatal("expired request replay renewed scope", err)
	}
	qualifyRawQueryRollback(t, ctx, admin)
}

func qualifyRawQueryRollback(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	db := stdlib.OpenDB(*admin.Config().ConnConfig.Copy())
	defer db.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	original, err := p.GetDBVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, end := context.WithTimeout(context.Background(), 30*time.Second)
		defer end()
		if _, err := p.UpTo(c, original); err != nil {
			t.Error(err)
		}
	}()
	if _, err = p.DownTo(ctx, 130); err == nil || !strings.Contains(err.Error(), "retained raw-query grants prevent rollback") {
		t.Fatal("retained raw downgrade", err)
	}
	head, err := p.GetDBVersion(ctx)
	if err != nil || head != 131 {
		t.Fatal("raw refusal changed schema", head, err)
	}
}
