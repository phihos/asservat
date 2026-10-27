package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestConnectorAPICollectorInputKeepsExactUIDAndVersion(t *testing.T) {
	for _, mode := range []string{"current", "replaced", "changed-version", "missing-pin"} {
		t.Run(mode, func(t *testing.T) {
			pins := []contracts.ConnectorAPIInput{{Kind: "ConfigMap", Name: RegionalInputs, UID: ownerID(81), ResourceVersion: "81"}, {Kind: "Secret", Name: RegionalEvidence, UID: ownerID(82), ResourceVersion: "82", DedicatedToAPI: true}, {Kind: "Secret", Name: RegionalNodes, UID: ownerID(83), ResourceVersion: "83", DedicatedToAPI: true}}
			calls := 0
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/asservat-connector/") {
					return false
				}
				calls++
				if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1" {
					t.Error("input check requested Secret payload")
				}
				for _, pin := range pins {
					if strings.HasSuffix(r.URL.Path, "/"+pin.Name) {
						uid, rv := pin.UID, pin.ResourceVersion
						if pin.Name == RegionalNodes {
							if mode == "replaced" {
								uid = ownerID(84)
							}
							if mode == "changed-version" {
								rv = "new"
							}
						}
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(meta.PartialObjectMetadata{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: meta.ObjectMeta{Name: pin.Name, Namespace: "asservat-connector", UID: types.UID(uid), ResourceVersion: rv}})
						return true
					}
				}
				t.Error("unexpected input metadata request", r.URL.Path)
				http.NotFound(w, r)
				return true
			})
			installed := contracts.ConnectorAPIContextSettings{Namespace: "asservat-connector", Inputs: pins}
			if mode == "missing-pin" {
				installed.Inputs = pins[:2]
			}
			g := ConnectorAPIExecutionProtection{attester: &ConnectorProcessAttester{client: f.client}, installed: installed, name: RegionalSettings}
			err := g.inputs(context.Background(), RegionalWorkload(contracts.RegionalOffer{}, true, true).Spec.Template.Spec)
			if mode == "current" {
				if err != nil || calls != 3 {
					t.Fatal("exact mounted inputs not verified", err, calls)
				}
			} else if !errors.Is(err, cfg.ErrChanged) {
				t.Fatal("unverified input passed", err)
			}
			if mode == "missing-pin" && calls != 0 {
				t.Fatal("input-set mismatch was silently filled from API", calls)
			}
		})
	}
}
