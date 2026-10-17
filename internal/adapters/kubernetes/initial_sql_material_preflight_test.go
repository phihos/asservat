package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestInitialSQLMaterialPreflightNeedsNoRootOrMutation(t *testing.T) {
	for _, mode := range []string{"valid", "duplicate-password", "wrong-uid"} {
		t.Run(mode, func(t *testing.T) {
			f := newPreparationBindingFixture(t)
			p := f.f.preparer(t)
			defer p.Close()
			reader, e := NewInitialSQLMaterialReader(p, f.material)
			if e != nil {
				t.Fatal(e)
			}
			f.f.mu.Lock()
			delete(f.f.objects, "/api/v1/namespaces/bootstrap/configmaps/prepare")
			object := f.f.objects["/api/v1/namespaces/bootstrap/secrets/initial-material"]
			if mode == "wrong-uid" {
				object["metadata"].(map[string]any)["uid"] = ownerID(990)
			}
			if mode == "duplicate-password" {
				v := f.password
				v.AuditPassword = v.PreparationPassword
				raw, _ := json.Marshal(v)
				object["data"].(map[string]any)["material.json"] = base64.StdEncoding.EncodeToString(raw)
				clear(raw)
			}
			before := map[string]int{}
			for k, v := range f.f.posts {
				before[k] = v
			}
			f.f.mu.Unlock()
			e = reader.CheckInitialSQLMaterial(context.Background())
			if (e == nil) != (mode == "valid") {
				t.Fatal("wrong preflight disposition", mode, e)
			}
			if _, _, e = reader.ReadInitialSQLMaterial(context.Background()); e == nil {
				t.Fatal("preflight manufactured an original root binding")
			}
			f.f.mu.Lock()
			defer f.f.mu.Unlock()
			if !equalJSON(before, f.f.posts) {
				t.Fatal("preflight caused an effect")
			}
		})
	}
}

func TestInitialSQLHistoryPreflightNeedsNoRootOrMutation(t *testing.T) {
	for _, mode := range []string{"valid", "preparation-password", "audit-password", "activation-password", "malformed-password", "wrong-uid"} {
		t.Run(mode, func(t *testing.T) {
			f := newPreparationBindingFixture(t)
			p := f.f.preparer(t)
			defer p.Close()
			reader, e := NewInitialSQLMaterialReader(p, f.material)
			if e != nil {
				t.Fatal(e)
			}
			password := base64.RawURLEncoding.EncodeToString([]byte("independent-history-password-123"))
			switch mode {
			case "preparation-password":
				password = f.password.PreparationPassword
			case "audit-password":
				password = f.password.AuditPassword
			case "activation-password":
				password = f.password.ActivationPassword
			case "malformed-password":
				password = "not-a-canonical-password"
			}
			f.f.mu.Lock()
			delete(f.f.objects, "/api/v1/namespaces/bootstrap/configmaps/prepare")
			if mode == "wrong-uid" {
				object := f.f.objects["/api/v1/namespaces/bootstrap/secrets/initial-material"]
				object["metadata"].(map[string]any)["uid"] = ownerID(990)
			}
			before := map[string]int{}
			for k, v := range f.f.posts {
				before[k] = v
			}
			f.f.mu.Unlock()
			// This is the check used by the actual loader before Declare. The
			// issuance reader below must continue rejecting a missing root.
			e = reader.CheckInitialSQLHistoryPassword(context.Background(), password)
			if (e == nil) != (mode == "valid") {
				t.Fatal("wrong history-password preflight disposition", mode, e)
			}
			if _, _, e = reader.ReadInitialSQLMaterial(context.Background()); e == nil {
				t.Fatal("preflight manufactured an original root binding")
			}
			f.f.mu.Lock()
			defer f.f.mu.Unlock()
			if !equalJSON(before, f.f.posts) || f.f.objects["/api/v1/namespaces/bootstrap/configmaps/prepare"] != nil {
				t.Fatal("preflight caused an effect")
			}
		})
	}
}
