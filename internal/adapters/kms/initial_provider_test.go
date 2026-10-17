package kms

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

type initialProviderFixture struct {
	mu             sync.Mutex
	server         *httptest.Server
	profile        contracts.InitialProviderProfile
	issuer         *InitialProviderIssuer
	parent         initialTokenLookup
	children       map[string]initialTokenLookup
	policies       map[string]string
	roleChange     func(*initialTokenRole)
	parentChange   func(*initialTokenLookup)
	childChange    func(*initialTokenLookup)
	issueMode      string
	posts          int
	policyMetadata map[string]any
	omitField      string
	shift          time.Duration
	accessorErrors []string
}

func newInitialProviderFixture(t *testing.T) *initialProviderFixture {
	t.Helper()
	now := time.Now().UTC()
	f := &initialProviderFixture{profile: contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: contracts.WorkerObjectReference{Name: "providers", UID: "20000000-0000-4000-8000-000000000001"}, IssuerPolicy: "initial-issuer", WrapRole: "initial-wrap-role", WrapPolicy: "initial-wrap-policy", UnwrapRole: "initial-unwrap-role", UnwrapPolicy: "initial-unwrap-policy"}, children: map[string]initialTokenLookup{}}
	f.parent = initialTokenLookup{Accessor: "original-parent", Type: "service", Policies: []string{f.profile.IssuerPolicy}, MaxTTL: 600, CreationTTL: 600, Issued: now.Add(-time.Minute), Expire: now.Add(5 * time.Minute), TTL: 300}
	var e error
	f.policies, e = InitialProviderPolicies(f.profile, "transit", "initial-audit")
	if e != nil {
		t.Fatal(e)
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	f.issuer, e = NewInitialProviderIssuer(f.server.URL, "original-issuer-token", "transit", "initial-audit", "20000000-0000-4000-8000-000000000002", "20000000-0000-4000-8000-000000000003", f.profile, f.server.Client(), func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return time.Now().Add(f.shift) })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(f.issuer.Close)
	return f
}
func (f *initialProviderFixture) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		if f.omitField != "" {
			body, _ := json.Marshal(v)
			var projected map[string]map[string]json.RawMessage
			if json.Unmarshal(body, &projected) == nil {
				parts := strings.SplitN(f.omitField, ".", 2)
				if len(parts) == 2 {
					delete(projected[parts[0]], parts[1])
				}
				v = projected
			}
		}
		_ = json.NewEncoder(w).Encode(v)
	}
	token := r.Header.Get("X-Vault-Token")
	if r.URL.Path == "/v1/auth/token/lookup-self" {
		d, ok := f.children[token]
		if ok && f.childChange != nil {
			f.childChange(&d)
		}
		if token == "original-issuer-token" {
			d = f.parent
			ok = true
			if f.parentChange != nil {
				f.parentChange(&d)
			}
		}
		if !ok {
			w.WriteHeader(403)
			reply(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		reply(map[string]any{"data": d})
		return
	}
	if r.URL.Path == "/v1/auth/token/lookup-accessor" || r.URL.Path == "/v1/auth/token/revoke-accessor" {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		found := ""
		var d initialTokenLookup
		for key, value := range f.children {
			if value.Accessor == body["accessor"] {
				found = key
				d = value
				break
			}
		}
		if found == "" {
			w.WriteHeader(400)
			errors := f.accessorErrors
			if errors == nil {
				errors = []string{"invalid accessor"}
			}
			reply(map[string]any{"errors": errors})
			return
		}
		if r.URL.Path == "/v1/auth/token/lookup-accessor" {
			reply(map[string]any{"data": d})
			return
		}
		delete(f.children, found)
		if f.issueMode == "lost-revoke" {
			w.WriteHeader(503)
			reply(map[string]any{"errors": []string{"MUST-NOT-LEAK"}})
			return
		}
		w.WriteHeader(204)
		return
	}
	if token != "original-issuer-token" {
		w.WriteHeader(403)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/auth/token/roles/") {
		name := strings.TrimPrefix(r.URL.Path, "/v1/auth/token/roles/")
		policy := f.profile.WrapPolicy
		if name == f.profile.UnwrapRole {
			policy = f.profile.UnwrapPolicy
		}
		d := initialTokenRole{Name: name, Allowed: []string{policy}, NoDefault: true, Type: "service", TokenMaxTTL: 900}
		if f.roleChange != nil {
			f.roleChange(&d)
		}
		reply(map[string]any{"data": d})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/sys/policies/acl/") {
		name := strings.TrimPrefix(r.URL.Path, "/v1/sys/policies/acl/")
		data := map[string]any{"name": name, "policy": f.policies[name], "version": 1, "cas_required": false, "allow_wildcards_in_identity_templates": false, "allow_slashes_in_identity_templates": false}
		for key, value := range f.policyMetadata {
			data[key] = value
		}
		reply(map[string]any{"data": data})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/auth/token/create/") {
		f.posts++
		var body struct {
			Policies  []string          `json:"policies"`
			Meta      map[string]string `json:"meta"`
			TTL       string            `json:"ttl"`
			Type      string            `json:"type"`
			Renewable bool              `json:"renewable"`
			Orphan    bool              `json:"no_parent"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ttl, _ := time.ParseDuration(body.TTL)
		now := time.Now().UTC()
		role := strings.TrimPrefix(r.URL.Path, "/v1/auth/token/create/")
		value := "original-child-" + strconv.Itoa(f.posts)
		accessor := "original-accessor-" + strconv.Itoa(f.posts)
		d := initialTokenLookup{Accessor: accessor, Type: "service", Policies: body.Policies, MaxTTL: int64(ttl / time.Second), CreationTTL: int64(ttl / time.Second), Issued: now, Expire: now.Add(ttl), TTL: int64(ttl / time.Second), Role: role, Path: "auth/token/create/" + role, Meta: body.Meta}
		f.children[value] = d
		if f.issueMode == "lost" {
			w.WriteHeader(503)
			reply(map[string]any{"errors": []string{"MUST-NOT-LEAK"}})
			return
		}
		if f.issueMode == "late" {
			f.shift = 6 * time.Second
		}
		if f.issueMode == "oversize" {
			value = strings.Repeat("x", 1025)
		}
		auth := map[string]any{"client_token": value, "accessor": accessor, "token_type": "service", "policies": body.Policies, "token_policies": body.Policies, "metadata": body.Meta, "lease_duration": int64(ttl / time.Second), "renewable": false, "orphan": false, "num_uses": 0, "entity_id": ""}
		if f.issueMode == "orphan" {
			auth["orphan"] = true
		}
		if f.issueMode == "extra-policy" {
			auth["policies"] = []string{body.Policies[0], "default"}
		}
		reply(map[string]any{"auth": auth})
		return
	}
	w.WriteHeader(404)
}
func (f *initialProviderFixture) claim(t *testing.T) (contracts.InitialProviderParent, contracts.InitialProviderIssue) {
	t.Helper()
	parent, _, e := f.issuer.Check(context.Background(), time.Now().Add(15*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	return parent, contracts.InitialProviderIssue{ID: "20000000-0000-4000-8000-000000000004", StartedAt: now, Until: now.Add(5 * time.Second), ExpiresBefore: parent.ExpiresAt}
}
func TestInitialProviderPositiveResponseRetainsOriginalDates(t *testing.T) {
	f := newInitialProviderFixture(t)
	parent, claim := f.claim(t)
	got, e := f.issuer.Issue(context.Background(), "wrap", claim, parent)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.issuer.Verify(context.Background(), "wrap", claim, parent, got); e != nil {
		t.Fatal(e)
	}
	if e = f.issuer.Verify(context.Background(), "unwrap", claim, parent, got); e == nil {
		t.Fatal("opposite purpose accepted")
	}
	changed := got
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Second)
	if e = f.issuer.Verify(context.Background(), "wrap", claim, parent, changed); e == nil {
		t.Fatal("renewed expiry accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts != 1 {
		t.Fatal("verification repeated issuance")
	}
}
func TestInitialProviderRejectsUnsafeRoleBeforeIssue(t *testing.T) {
	cases := map[string]func(*initialTokenRole){"orphan": func(v *initialTokenRole) { v.Orphan = true }, "renewable": func(v *initialTokenRole) { v.Renewable = true }, "default": func(v *initialTokenRole) { v.NoDefault = false }, "batch": func(v *initialTokenRole) { v.Type = "batch" }, "period": func(v *initialTokenRole) { v.TokenPeriod = 30 }, "legacy-period": func(v *initialTokenRole) { v.Period = 30 }, "glob": func(v *initialTokenRole) { v.AllowedGlob = []string{"*"} }, "alias": func(v *initialTokenRole) { v.Aliases = []string{"human"} }, "cidr": func(v *initialTokenRole) { v.Bound = []string{"0.0.0.0/0"} }, "ttl": func(v *initialTokenRole) { v.TokenMaxTTL = 901 }, "uses": func(v *initialTokenRole) { v.Uses = 1 }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newInitialProviderFixture(t)
			f.roleChange = change
			if _, _, e := f.issuer.Check(context.Background(), time.Now().Add(15*time.Minute)); e == nil {
				t.Fatal("unsafe role accepted")
			}
			if f.posts != 0 {
				t.Fatal("read-only preflight issued token")
			}
		})
	}
}
func TestInitialProviderRejectsBroaderPolicyAndIssuer(t *testing.T) {
	for _, mode := range []string{"wildcard", "extra-capability", "identity", "root", "renewable", "orphan", "parent-after-original-interval"} {
		t.Run(mode, func(t *testing.T) {
			f := newInitialProviderFixture(t)
			switch mode {
			case "wildcard":
				f.policies[f.profile.WrapPolicy] = `{"path":{"*":{"capabilities":["update"]}}}`
			case "extra-capability":
				f.policies[f.profile.WrapPolicy] = strings.Replace(f.policies[f.profile.WrapPolicy], `["update"]`, `["update","sudo"]`, 1)
			case "identity":
				f.parentChange = func(v *initialTokenLookup) { v.IdentityPolicies = []string{"admin"} }
			case "root":
				f.parentChange = func(v *initialTokenLookup) { v.Policies = []string{"root"} }
			case "renewable":
				f.parentChange = func(v *initialTokenLookup) { v.Renewable = true }
			case "orphan":
				f.parentChange = func(v *initialTokenLookup) { v.Orphan = true }
			}
			limit := time.Now().Add(15 * time.Minute)
			if mode == "parent-after-original-interval" {
				limit = time.Now().Add(time.Minute)
			}
			if _, _, e := f.issuer.Check(context.Background(), limit); e == nil {
				t.Fatal("broader issuer/policy accepted")
			}
			if f.posts != 0 {
				t.Fatal("preflight issued token")
			}
		})
	}
}
func TestInitialProviderUncertainOrLateCreateNeverReturnsCredential(t *testing.T) {
	for _, mode := range []string{"lost", "late", "oversize", "orphan", "extra-policy"} {
		t.Run(mode, func(t *testing.T) {
			f := newInitialProviderFixture(t)
			parent, claim := f.claim(t)
			f.issueMode = mode
			got, e := f.issuer.Issue(context.Background(), "wrap", claim, parent)
			if e == nil || got.Token != "" || strings.Contains(e.Error(), "MUST-NOT-LEAK") {
				t.Fatal("unsafe provider response exposed")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.posts != 1 {
				t.Fatal("provider POST retried", f.posts)
			}
		})
	}
}

func TestInitialProviderRetirementRequiresOriginalPositiveResponseAndLiveDenial(t *testing.T) {
	for _, mode := range []string{"positive", "lost-revoke", "forged-reply"} {
		t.Run(mode, func(t *testing.T) {
			f := newInitialProviderFixture(t)
			parent, claim := f.claim(t)
			got, e := f.issuer.Issue(context.Background(), "wrap", claim, parent)
			if e != nil {
				t.Fatal(e)
			}
			claim.Response = &got
			f.issueMode = mode
			target := got
			if mode == "forged-reply" {
				target.Accessor = "foreign"
			}
			until, e := f.issuer.Revoke(context.Background(), "wrap", claim, parent, target)
			if mode == "forged-reply" {
				if e == nil {
					t.Fatal("foreign credential retired")
				}
				return
			}
			if e != nil || !time.Now().Before(until) {
				t.Fatal("positive provider retirement", e)
			}
			if _, e = f.issuer.Revoke(context.Background(), "wrap", claim, parent, got); e != nil {
				t.Fatal("exact retirement retry", e)
			}
			if e = f.issuer.Verify(context.Background(), "wrap", claim, parent, got); e == nil {
				t.Fatal("retired credential accepted")
			}
			if f.posts != 1 {
				t.Fatal("retirement issued credential")
			}
		})
	}
}

func TestInitialProviderRequiresExplicitSafetyFields(t *testing.T) {
	for _, field := range []string{"data.orphan", "data.renewable", "data.token_no_default_policy", "data.token_explicit_max_ttl"} {
		t.Run(field, func(t *testing.T) {
			f := newInitialProviderFixture(t)
			f.omitField = field
			if _, _, e := f.issuer.Check(context.Background(), time.Now().Add(15*time.Minute)); e == nil {
				t.Fatal("missing role safety value accepted as zero")
			}
		})
	}
	for _, field := range []string{"auth.orphan", "auth.renewable", "auth.entity_id", "auth.num_uses", "auth.metadata"} {
		t.Run(field, func(t *testing.T) {
			f := newInitialProviderFixture(t)
			parent, claim := f.claim(t)
			f.omitField = field
			if got, e := f.issuer.Issue(context.Background(), "wrap", claim, parent); e == nil || got.Token != "" {
				t.Fatal("missing issuance safety value accepted as zero")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.posts != 1 {
				t.Fatal("missing response caused another issuance")
			}
		})
	}
}
