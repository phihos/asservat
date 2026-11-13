package providerconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"asservat.local/asservat/internal/contracts"
	bao "github.com/openbao/openbao/api/v2"
)

// fakeOpenBao keeps written paths and serves the reads EnsureOpenBaoSetup
// performs; it records every write.
type fakeOpenBao struct {
	mu     sync.Mutex
	data   map[string]map[string]any
	mounts map[string]bool
	auth   map[string]bool
	roots  map[string]bool
	writes []string
}

func (f *fakeOpenBao) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	reply := func(data map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}
	list := func(set map[string]bool) {
		out := map[string]any{}
		for m := range set {
			out[m+"/"] = map[string]any{}
		}
		reply(out)
	}
	switch {
	case r.Method == http.MethodGet && path == "sys/mounts":
		list(f.mounts)
	case r.Method == http.MethodGet && path == "sys/auth":
		list(f.auth)
	case r.Method == "LIST" || r.URL.Query().Get("list") == "true":
		m := strings.TrimSuffix(path, "/issuers")
		if !f.roots[m] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		reply(map[string]any{"keys": []string{"default"}})
	case r.Method == http.MethodGet:
		d, ok := f.data[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errors":[]}`)
			return
		}
		reply(d)
	default:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.writes = append(f.writes, path)
		switch {
		case strings.HasPrefix(path, "sys/mounts/"):
			f.mounts[strings.TrimPrefix(path, "sys/mounts/")] = true
		case strings.HasPrefix(path, "sys/auth/"):
			f.auth[strings.TrimPrefix(path, "sys/auth/")] = true
		case strings.HasSuffix(path, "/root/generate/internal"):
			f.roots[strings.TrimSuffix(path, "/root/generate/internal")] = true
		default:
			f.data[path] = body
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func setupOpenBaoInput() OpenBaoSetupInput {
	return OpenBaoSetupInput{Name: "asservat", Namespace: "asservat", InstallationID: "10000000-0000-4000-8000-000000000001", ClusterID: "10000000-0000-4000-8000-000000000002", IssuerEpoch: "10000000-0000-4000-8000-000000000003",
		Accounts: map[string]string{"hub-api": "asservat-hub-api", "hub-worker": "asservat-hub-worker", "federation": "asservat-federation", "publisher": "asservat-publisher"}}
}

func TestEnsureOpenBaoSetupIsIdempotent(t *testing.T) {
	f := &fakeOpenBao{data: map[string]map[string]any{}, mounts: map[string]bool{}, auth: map[string]bool{}, roots: map[string]bool{}}
	server := httptest.NewServer(f)
	defer server.Close()
	config := bao.DefaultConfig()
	config.Address = server.URL
	config.MaxRetries = 0
	client, err := bao.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("setup")
	in := setupOpenBaoInput()
	var out bytes.Buffer
	if err = EnsureOpenBaoSetup(context.Background(), client, in, &out); err != nil {
		t.Fatal(err, out.String())
	}
	first := append([]string(nil), f.writes...)
	n := OpenBaoNamesFor(in.InstallationID)
	for _, path := range []string{"sys/mounts/" + contracts.SmallOpenBaoAuditMount, "sys/auth/" + contracts.SmallOpenBaoOwnerAuthMount, contracts.SmallOpenBaoOwnerPKIMount + "/root/generate/internal",
		contracts.SmallOpenBaoAuditMount + "/keys/" + n.DeletionSigningKey, contracts.SmallOpenBaoTransitMount + "/keys/" + n.WorkSigningKey,
		contracts.SmallOpenBaoWorkerPKIMount + "/roles/" + n.VerifierRole, "sys/policies/acl/asservat-hub-worker-cleanup-sign",
		"auth/" + contracts.SmallOpenBaoConfigurationAuthMount + "/role/asservat-hub-worker-audit-wrap", "auth/" + contracts.SmallOpenBaoOwnerAuthMount + "/role/asservat-publisher-verifier-sign"} {
		if !contains(first, path) {
			t.Fatal("first run did not write", path)
		}
	}
	role := f.data["auth/"+contracts.SmallOpenBaoOwnerAuthMount+"/role/asservat-federation-client-sign"]
	if role["audience"] != contracts.FederationProviderAudience(in.InstallationID, in.ClusterID) || role["bound_service_account_names"].([]any)[0] != "asservat-federation" || role["bound_service_account_namespaces"].([]any)[0] != "asservat" {
		t.Fatal("federation role binding", role)
	}
	var acl ownerProviderACL
	if json.Unmarshal([]byte(f.data["sys/policies/acl/asservat-hub-api-bootstrap-channel"]["policy"].(string)), &acl) != nil || len(acl.Path) != 4 {
		t.Fatal("channel policy", f.data["sys/policies/acl/asservat-hub-api-bootstrap-channel"])
	}
	f.writes = nil
	out.Reset()
	if err = EnsureOpenBaoSetup(context.Background(), client, in, &out); err != nil {
		t.Fatal(err)
	}
	for _, path := range f.writes {
		if strings.Contains(path, "/keys/") || strings.HasPrefix(path, "sys/mounts/") || strings.HasPrefix(path, "sys/auth/") || strings.HasSuffix(path, "/root/generate/internal") || strings.HasPrefix(path, "sys/policies/acl/") {
			t.Fatal("second run recreated", path)
		}
	}
	if !contains(f.writes, "auth/"+contracts.SmallOpenBaoConfigurationAuthMount+"/role/asservat-hub-worker-audit-wrap") || !contains(f.writes, contracts.SmallOpenBaoOwnerPKIMount+"/roles/"+n.OwnerServerRole) {
		t.Fatal("second run did not upsert roles", f.writes)
	}
	if !strings.Contains(out.String(), "unchanged: sys/policies/acl/asservat-hub-api-audit-wrap") {
		t.Fatal("unchanged policy not reported", out.String())
	}
	bad := in
	bad.Accounts = map[string]string{"hub-api": "x"}
	if EnsureOpenBaoSetup(context.Background(), client, bad, &out) == nil {
		t.Fatal("missing component account accepted")
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestOpenBaoRoleName(t *testing.T) {
	if OpenBaoRoleName("asservat", "hub-api", "audit-wrap") != "asservat-hub-api-audit-wrap" {
		t.Fatal("role name")
	}
	for _, c := range [][3]string{{"", "hub-api", "x"}, {"a", "", "x"}, {"a", "b", ""}, {"a/b", "hub-api", "x"}, {strings.Repeat("a", 130), "b", "c"}} {
		if OpenBaoRoleName(c[0], c[1], c[2]) != "" {
			t.Fatal("invalid name accepted", c)
		}
	}
}
