package kubernetes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ownerConfigurationTestRoot(t *testing.T, now time.Time) []byte {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestOwnerConfigurationClosedSnapshot(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	root := base64.StdEncoding.EncodeToString(ownerConfigurationTestRoot(t, now))
	for _, mode := range []string{"valid", "unknown", "missing-suspended", "null-suspended", "case-alias", "duplicate", "trailing", "foreign-installation", "foreign-cluster", "foreign-namespace", "invalid-port", "invalid-name", "invalid-uid", "empty-roots", "duplicate-roots", "invalid-root", "expired-root", "invalid-revision"} {
		t.Run(mode, func(t *testing.T) {
			v := map[string]any{"format": "asservat-hub-owner-configuration/v1", "installationID": ownerID(1), "clusterID": permissionCluster, "issuerEpoch": ownerID(2), "revision": 1, "suspended": false, "namespace": map[string]any{"name": permissionControl.Name, "uid": ownerID(3)}, "service": map[string]any{"name": "owner", "uid": ownerID(4)}, "deployment": map[string]any{"name": "hub", "uid": ownerID(5)}, "serviceAccount": map[string]any{"name": "hub", "uid": ownerID(6)}, "port": 9443, "issuerRoots": []string{root}}
			switch mode {
			case "unknown":
				v["privateKey"] = "forbidden"
			case "missing-suspended":
				delete(v, "suspended")
			case "null-suspended":
				v["suspended"] = nil
			case "case-alias":
				v["Revision"] = 1
				delete(v, "revision")
			case "foreign-installation":
				v["installationID"] = ownerID(99)
			case "foreign-cluster":
				v["clusterID"] = ownerID(99)
			case "foreign-namespace":
				v["namespace"].(map[string]any)["uid"] = ownerID(99)
			case "invalid-port":
				v["port"] = 443
			case "invalid-name":
				v["deployment"].(map[string]any)["name"] = "../hub"
			case "invalid-uid":
				v["service"].(map[string]any)["uid"] = "caller-selected"
			case "empty-roots":
				v["issuerRoots"] = []string{}
			case "duplicate-roots":
				v["issuerRoots"] = []string{root, root}
			case "invalid-root":
				v["issuerRoots"] = []string{"AQ=="}
			case "invalid-revision":
				v["revision"] = 0
			}
			b, _ := json.Marshal(v)
			raw := string(b)
			if mode == "duplicate" {
				raw = strings.Replace(raw, `"revision":1`, `"revision":1,"revision":1`, 1)
			}
			if mode == "trailing" {
				raw += `{}`
			}
			var payload atomic.Value
			payload.Store(raw)
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				switch r.URL.Path {
				case "/api/v1/namespaces/" + permissionControl.Name:
					permissionReply(w, permissionNamespace(permissionControl.Name, ownerID(3)))
					return true
				case "/api/v1/namespaces/" + permissionControl.Name + "/configmaps/owner-pool":
					permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "owner-pool", "namespace": permissionControl.Name, "uid": ownerID(7), "resourceVersion": "1"}, "data": map[string]string{"owner-pool.json": payload.Load().(string)}})
					return true
				}
				return false
			})
			f.client.control.UID = ownerID(3)
			if mode == "expired-root" {
				f.clock.Store(now.Add(2 * time.Hour).UnixNano())
			}
			s := &OwnerConfigurationSource{client: f.client, name: "owner-pool", uid: ownerID(7), installation: ownerID(1)}
			c, until, err := s.snapshot(context.Background())
			if mode != "valid" {
				if err == nil {
					t.Fatal("invalid owner configuration accepted")
				}
				return
			}
			if err != nil || !c.Pool.Valid() || !c.Revision.Valid() || !until.Equal(now.Add(time.Hour)) {
				t.Fatal("valid owner configuration", err)
			}
			pretty, _ := json.MarshalIndent(v, "", "  ")
			payload.Store(string(pretty))
			again, _, err := s.snapshot(context.Background())
			if err != nil || !c.Equal(again) {
				t.Fatal("canonical configuration identity changed", err)
			}
		})
	}
}
