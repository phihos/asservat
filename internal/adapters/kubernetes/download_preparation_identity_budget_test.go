package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// This adds actual identity policy HTTP, identity admission/current-request
// ownership and ContextDownloadAuthority to the production preparation chain.
// Claims/token cryptography, SQL permissions/catalog/retention and the existing
// Job/audit ports remain explicit synthetic inputs. It qualifies neither an IdP
// nor installed authorization, SQL, Kubernetes admission or native transfer.
type preparationIdentityBudget struct {
	*preparationPhaseBudget
	claims                                       identity.Claims
	identityRequests, identityPolicyReads        atomic.Int32
	identityClockOffset                          atomic.Int64
	permissionDelay                              time.Duration
	tokenChecks, permissions, catalog, retention int
}

func (f *preparationIdentityBudget) Verify(ctx context.Context, token string) (identity.Claims, error) {
	if token != "synthetic-download-token" {
		f.t.Fatal("identity verifier received another credential")
	}
	f.tokenChecks++
	claims := f.claims
	claims.Groups, claims.Scopes = slices.Clone(claims.Groups), slices.Clone(claims.Scopes)
	return claims, f.step(ctx, "verify-token")
}

func (f *preparationIdentityBudget) Permissions(ctx context.Context, target value.Target) (value.Projection, error) {
	f.permissions++
	if target != f.record.Retained.Input.Target {
		f.t.Fatal("permission read changed the exact target")
	}
	if f.permissions == 1 && f.permissionDelay > 0 {
		timer := time.NewTimer(f.permissionDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return value.Projection{}, ctx.Err()
		}
	}
	p := value.Projection{Target: target, Revision: identity.Revision{UID: f.a.PermissionEpoch, Generation: f.a.PermissionSequence, Digest: f.a.ProjectionDigest}, ObservedAt: f.started, FreshUntil: f.until, DeniesComplete: true, DeniesObservedAt: f.started, DeniesFreshUntil: f.until}
	for _, audience := range f.record.Audience {
		p.Allows = append(p.Allows, value.CurrentAssignment{Audience: audience, ObservedAt: f.started, FreshUntil: f.until})
	}
	return p, f.step(ctx, "permissions")
}

func (f *preparationIdentityBudget) ContextDownloadEvidence(ctx context.Context, id string) (authapp.ContextDownloadEvidence, error) {
	f.catalog++
	if id != f.a.Scope.ArtifactID {
		f.t.Fatal("catalog read changed the selected artifact")
	}
	return f.record, f.step(ctx, "catalog")
}

func (f *preparationIdentityBudget) ResolveRetained(ctx context.Context, in privacy.Input, old privacy.Deadlines, origins []artifact.RetentionRule) (privacy.RetainedResolution, error) {
	f.retention++
	if !reflect.DeepEqual(in, f.record.Retained.Input) || old != f.record.Retained.Effective || !reflect.DeepEqual(origins, f.record.Retained.OriginPolicies) {
		f.t.Fatal("retention read changed original artifact facts")
	}
	return privacy.RetainedResolution{Target: in.Target, PolicyRevision: f.a.Retention.Policy, PurposeRef: f.record.PurposeRef, Policies: slices.Clone(origins), Deadlines: old, Proof: f.a.Retention, ValidUntil: f.until}, f.step(ctx, "retention")
}

func (f *preparationIdentityBudget) identityService(t *testing.T) identities.Service {
	t.Helper()
	observer := f.downloadPolicyBudgetFixture.source.client
	client, ok := observer.api.(*rest.RESTClient)
	if !ok || client.Client == nil {
		t.Fatal("fixture does not expose its verified loopback TLS transport")
	}
	endpoint := observer.api.Get().URL()
	const userAgent = "asservat-download-identity-budget"
	// ADR-173 installs a separate standard 20/20 identity client. Reuse only
	// the verified TLS transport/endpoint, never the policy client's limiter.
	identityObserver, err := NewPermissionClient(&rest.Config{Host: endpoint.Scheme + "://" + endpoint.Host, Transport: client.Client.Transport, UserAgent: userAgent}, observer.clusterID, observer.control, func() time.Time {
		return time.Now().Add(time.Duration(f.identityClockOffset.Load()))
	})
	if err != nil {
		t.Fatal("independent identity client", err)
	}
	if identityObserver.api.GetRateLimiter().QPS() != 20 || identityObserver.SharesLimiter(observer) || identityObserver.SharesLimiter(f.downloadPolicyBudgetFixture.source.protection.probe) {
		t.Fatal("identity fixture changed the installed independent standard limiter")
	}
	const name = "download-identity"
	uid := ownerID(19200)
	settings := contracts.IdentitySettings{SchemaVersion: "identity-settings/v1", Revision: 1, Issuer: f.claims.Issuer, Clients: []contracts.IdentityClient{{ID: f.claims.ClientID, Kind: string(identity.Human), ClassQualified: true}}, EligibleSubjects: []contracts.IdentitySubject{}, EligibleGroups: []string{"team"}, GroupsAtIssueQualified: true, GroupMaxAgeSeconds: 300}
	encoded, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	object := &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: observer.control.Name, UID: types.UID(uid), ResourceVersion: "1"}, Data: map[string]string{"identity.json": string(encoded)}}
	path := "/api/v1/namespaces/" + observer.control.Name + "/configmaps/" + name
	f.downloadPolicyBudgetFixture.mu.Lock()
	f.downloadPolicyBudgetFixture.before = func(w http.ResponseWriter, r *http.Request) bool {
		if r.UserAgent() != userAgent {
			return false
		}
		f.identityRequests.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer administrator" {
			t.Error("identity observation changed its read-only credential")
			http.Error(w, "unexpected identity observation", http.StatusForbidden)
			return true
		}
		if r.URL.Path == path {
			f.identityPolicyReads.Add(1)
			permissionReply(w, object)
			return true
		}
		if r.URL.Path != "/api/v1/namespaces/"+observer.control.Name {
			t.Error("identity observation selected an unexpected resource")
			http.NotFound(w, r)
			return true
		}
		return false
	}
	f.downloadPolicyBudgetFixture.mu.Unlock()
	policies, err := NewIdentityPolicyClient(identityObserver, name, uid, f.claims.Issuer)
	if err != nil {
		t.Fatal("identity policy reader", err)
	}
	return identities.Service{Tokens: f, Policies: policies, Now: time.Now}
}

func TestDownloadPreparationFirstJobFitsOriginalIdentityAndPolicyBudget(t *testing.T) {
	testDownloadPreparationIdentityBudget(t, false)
}

func TestDownloadPreparationNearExpiredIdentityObservation(t *testing.T) {
	testDownloadPreparationIdentityBudget(t, true)
}

func testDownloadPreparationIdentityBudget(t *testing.T, nearExpiry bool) {
	t.Helper()
	base, coordinator := newPreparationPhaseBudget(t)
	f := &preparationIdentityBudget{preparationPhaseBudget: base}
	p := f.a.Scope.Principal
	f.claims = identity.Claims{Issuer: p.Issuer, Subject: p.Subject, ClientID: p.ClientID, Scopes: []string{"evidence:read", "evidence:download"}, Groups: []string{"team"}, IssuedAt: f.started, ExpiresAt: f.started.Add(time.Minute), KeyUntil: f.started.Add(time.Minute)}
	service := f.identityService(t)
	wantIdentityReads := int32(1)
	if nearExpiry {
		// Prime through real TLS/API/decode with an older source clock. Restore
		// real time without editing the retained observation or its cutoff.
		f.identityClockOffset.Store(int64(-30*time.Second + 250*time.Millisecond))
		primed, err := service.Policies.IdentityPolicy(t.Context(), f.claims.Issuer)
		f.identityClockOffset.Store(0)
		if err != nil || primed.Validate(time.Now()) != nil || time.Until(primed.FreshUntil) >= 250*time.Millisecond {
			t.Fatal("near-expiry observation was not successfully primed", err)
		}
		f.permissionDelay = 350 * time.Millisecond
		wantIdentityReads++
	}
	f.authority = authapp.ContextDownloadAuthority{RootID: f.a.Scope.RootID, Identities: service, Permissions: f, Catalog: f, Retention: f, Environment: f.environment, Now: time.Now}
	call, cancel := context.WithDeadline(t.Context(), f.until)
	defer cancel()
	current, initial, err := identities.NewBearerRequest(call, service, "synthetic-download-token", time.Now)
	if err != nil || initial.Principal != p || !initial.Valid(time.Now()) {
		t.Fatal("initial actual identity composition", err)
	}
	t.Logf("near_expiry=%t initial_identity_remaining=%s original_request_remaining=%s", nearExpiry, time.Until(initial.ValidUntil), time.Until(f.until))
	out, err := coordinator.PrepareContextDownload(call, current, f.a.Scope.ArtifactID, "original-download-key")
	t.Logf("elapsed=%s original_interval=%s authority_checks=%d raw_policy_reads=%d completed_policy_reads=%d policy_observer=%d identity_observer=%d identity_policy_reads=%d token_checks=%d permissions=%d catalog=%d retention=%d probe=%d denied=%d created=%t recorded=%t job_pending=%t continued=%t err=%v", time.Since(f.started), f.until.Sub(f.started), f.checks, f.policyReads, f.policiesOK, f.observer.Load()-f.identityRequests.Load(), f.identityRequests.Load(), f.identityPolicyReads.Load(), f.tokenChecks, f.permissions, f.catalog, f.retention, f.probe.Load(), f.denied.Load(), f.created, f.recorded, f.pending, out.ContinuePreparation, err)
	t.Logf("production_path=%v", f.steps)
	if err != nil || !out.ContinuePreparation || out.Session.State != artifact.DownloadPreparing || out.Metadata != nil || !f.created || !f.recorded || !f.pending {
		t.Fatal("first acknowledged Job Pending did not fit the original five-second request with actual identity and authority composition")
	}
	if f.checks != 1 || f.tokenChecks != 6 || f.permissions != 2 || f.catalog != 1 || f.retention != 1 {
		t.Fatalf("preparation reconstructed operation authority: gates=%d token=%d permission=%d catalog=%d retention=%d; want 1/6/2/1/1", f.checks, f.tokenChecks, f.permissions, f.catalog, f.retention)
	}
	if f.policyReads != 1 || f.policiesOK != 1 || f.observer.Load()-f.identityRequests.Load() != 14 || f.probe.Load() != 3 || f.denied.Load() != 1 || f.identityPolicyReads.Load() != wantIdentityReads || f.identityRequests.Load() != 3*wantIdentityReads || f.tokenChecks < 2 || f.permissions < 2 || f.catalog < 1 || f.retention < 1 {
		t.Fatal("preparation skipped or repeated a required composed observation")
	}
}
