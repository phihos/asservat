package bootstrap

import (
	"asservat.local/asservat/internal/contracts"
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestOwnerCapacityProbePreservesExactOptionalAccount(t *testing.T) {
	in, dir, c := ownerInputFixture(t)
	b, e := json.Marshal(c)
	if e != nil || bytes.Contains(b, []byte(`"capacityProbe"`)) {
		t.Fatal("changed legacy omission", e)
	}
	for _, mode := range []string{"valid", "omitted", "bad-name", "missing-uid", "bad-uid"} {
		t.Run(mode, func(t *testing.T) {
			p := contracts.OwnerDeploymentCapacityProbe{ServiceAccount: contracts.WorkerObjectReference{Name: "configuration-worker", UID: runtimeID}}
			switch mode {
			case "bad-name":
				p.ServiceAccount.Name = "../foreign"
			case "missing-uid":
				p.ServiceAccount.UID = ""
			case "bad-uid":
				p.ServiceAccount.UID = "other"
			}
			c.CapacityProbe = &p
			if mode == "omitted" {
				c.CapacityProbe = nil
			}
			writeOwnerJSON(t, dir, "deployment.json", c)
			got, e := readOwnerInputs(context.Background(), in.files)
			if mode != "valid" && mode != "omitted" {
				if e == nil {
					t.Fatal("malformed account accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			v, e := ownerDeploymentCapacityProbe(got.config.CapacityProbe)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "omitted" {
				if v != nil {
					t.Fatal("inferred account")
				}
				return
			}
			if v == nil || v.ServiceAccount != p.ServiceAccount.Name || v.ServiceAccountUID != p.ServiceAccount.UID {
				t.Fatal("lost original account")
			}
			p.ServiceAccount.UID = "changed"
			if v.ServiceAccountUID != runtimeID {
				t.Fatal("retained caller alias")
			}
		})
	}
}
