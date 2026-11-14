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
