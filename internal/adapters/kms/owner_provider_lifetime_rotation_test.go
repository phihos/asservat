package kms

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
)

// This synthetic TLS provider distinguishes fresh authentication identities.
// Clock advances test bounded local ownership, not actual 300-second expiry.
func TestOwnerProviderLifetimeHeldOldResponsePreventsThirdCredential(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	type tokenState struct {
		token, accessor string
		issue, end      time.Time
	}
	var mu sync.Mutex
	tokens := map[string]tokenState{}
	logins, revokes := 0, 0
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		now := f.control.now()
		metadata := map[string]string{"role": f.control.role, "service_account_name": f.control.account, "service_account_uid": f.control.accountUID, "service_account_namespace": f.control.namespace, "service_account_secret_name": ""}
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/auth/owner-auth/login":
			var input map[string]string
			if json.NewDecoder(r.Body).Decode(&input) != nil || input["role"] != f.control.role || input["jwt"] == "" {
				w.WriteHeader(403)
				return
			}
			logins++
			suffix := strconv.Itoa(logins)
			v := tokenState{"new-service-token-" + suffix, "new-accessor-" + suffix, now.Truncate(time.Second), now.Add(300 * time.Second)}
			tokens[v.token] = v
			a := ownerProviderAuthReply{ClientToken: v.token, Accessor: v.accessor, Policies: []string{f.control.role}, TokenPolicies: []string{f.control.role}, Metadata: metadata, Orphan: true, EntityID: "10000000-0000-4000-8000-000000000009", LeaseDuration: 300, Renewable: true, Type: "service"}
			_ = json.NewEncoder(w).Encode(ownerProviderControlReply{Auth: &a})
		case "GET /v1/auth/token/lookup-self":
			v, ok := tokens[r.Header.Get("X-Vault-Token")]
			if !ok {
				w.WriteHeader(403)
				return
			}
			value := initialTokenLookup{ID: v.token, Accessor: v.accessor, Policies: []string{f.control.role}, Path: "auth/owner-auth/login", Meta: metadata, Display: "kubernetes-original-owner", Orphan: true, Creation: v.issue.Unix(), CreationTTL: 300, Expire: v.end, TTL: int64(v.end.Sub(now) / time.Second), MaxTTL: 900, Entity: "10000000-0000-4000-8000-000000000009", Type: "service", Renewable: true, Issued: v.issue}
			raw, _ := json.Marshal(value)
			_ = json.NewEncoder(w).Encode(ownerProviderControlReply{Data: raw})
		case "POST /v1/auth/token/revoke-self":
			if _, ok := tokens[r.Header.Get("X-Vault-Token")]; !ok {
				w.WriteHeader(403)
				return
			}
			revokes++
			delete(tokens, r.Header.Get("X-Vault-Token"))
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	})
	s := newOwnerProviderLifetimeFixture(t, f, nil, nil, 2)
	if err := s.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := s.borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first.token)
	defer first.release()
	f.mu.Lock()
	f.shift = 301 * time.Second
	f.mu.Unlock()
	if err = s.refresh(context.Background()); err != nil {
		t.Fatal("first replacement", err)
	}
	second, err := s.borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second.token)
	defer second.release()
	if string(first.token) == string(second.token) {
		t.Fatal("fresh authentication reused original credential")
	}
	f.mu.Lock()
	f.shift = 602 * time.Second
	f.mu.Unlock()
	if err = s.refresh(context.Background()); err == nil {
		t.Fatal("unclosed old response admitted third token")
	}
	mu.Lock()
	beforeLogins, beforeRevokes := logins, revokes
	mu.Unlock()
	if beforeLogins != 2 || beforeRevokes != 0 {
		t.Fatal("held old response was revoked or replaced")
	}
	first.release()
	if err = s.refresh(context.Background()); err != nil {
		t.Fatal("joined old response did not permit bounded replacement", err)
	}
	mu.Lock()
	afterLogins, afterRevokes := logins, revokes
	mu.Unlock()
	if afterLogins != 3 || afterRevokes != 1 {
		t.Fatal("joined replacement did not retain exact finite effect counts")
	}
}
