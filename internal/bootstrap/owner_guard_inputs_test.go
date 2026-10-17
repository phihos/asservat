package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestOwnerGuardStartsExactOptionalProjection(t *testing.T) {
	in, dir, c := ownerInputFixture(t)
	legacy, e := json.Marshal(c)
	if e != nil || bytes.Contains(legacy, []byte(`"apiContextStarts"`)) {
		t.Fatal("legacy bytes changed", e)
	}
	base := contracts.OwnerDeploymentAPIContextStarts{CapacityAccount: contracts.WorkerObjectReference{Name: "capacity", UID: runtimeID}, ExecutionAccount: contracts.WorkerObjectReference{Name: "executor", UID: "22222222-2222-4222-8222-222222222222"}}
	for _, mode := range []string{"valid", "omitted", "same-name", "same-uid", "missing-uid", "bad-name"} {
		t.Run(mode, func(t *testing.T) {
			p := base
			switch mode {
			case "same-name":
				p.ExecutionAccount.Name = p.CapacityAccount.Name
			case "same-uid":
				p.ExecutionAccount.UID = p.CapacityAccount.UID
			case "missing-uid":
				p.CapacityAccount.UID = ""
			case "bad-name":
				p.CapacityAccount.Name = "../other"
			}
			c.APIContextStarts = &p
			if mode == "omitted" {
				c.APIContextStarts = nil
			}
			writeOwnerJSON(t, dir, "deployment.json", c)
			got, e := readOwnerInputs(context.Background(), in.files)
			if mode != "valid" && mode != "omitted" {
				if e == nil {
					t.Fatal("malformed guard facet accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			v, e := ownerDeploymentStarts(got.config.APIContextStarts)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "omitted" {
				if v != nil {
					t.Fatal("inferred omitted facet")
				}
				return
			}
			if v == nil || v.CapacityAccount != p.CapacityAccount.Name || v.CapacityAccountUID != p.CapacityAccount.UID || v.ExecutionAccount != p.ExecutionAccount.Name || v.ExecutionAccountUID != p.ExecutionAccount.UID {
				t.Fatal("guard scope not preserved")
			}
			p.CapacityAccount.UID = "changed"
			if v.CapacityAccountUID != base.CapacityAccount.UID {
				t.Fatal("mutable input alias retained")
			}
		})
	}
}
