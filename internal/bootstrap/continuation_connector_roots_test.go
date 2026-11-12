package bootstrap

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestContinuationBundledConnectorRootsComeFromExactExistingIssuer(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		f := newContinuationBaoFixture(t, "")
		input := f.input()
		input.Public = &contracts.InstallerPublicSettings{Federation: &contracts.InstallerFederationSettings{}}
		if explicit {
			input.Public.Federation.ConnectorPKIMount = contracts.SmallOpenBaoConnectorPKIMount
			input.Public.Federation.ConnectorIssuerRootsPEM = f.connectorIssuer
		}
		ctx, end := context.WithTimeout(t.Context(), time.Minute)
		p, err := resolveInstallerContinuationKeyServiceWithOpen(ctx, f.base.files, &input, f.original(t), f.base.config, f.open)
		end()
		if err != nil {
			t.Fatal(err)
		}
		p.Close()
		if input.Public.Federation.ConnectorPKIMount != contracts.SmallOpenBaoConnectorPKIMount || input.Public.Federation.ConnectorIssuerRootsPEM != f.connectorIssuer || input.Public.Federation.ConnectorIssuerRootsPEM == f.issuer {
			t.Fatal("connector root replaced by owner CA")
		}
		if f.base.requests["GET /v1/"+contracts.SmallOpenBaoConnectorPKIMount+"/cert/ca"] != 1 {
			t.Fatal("connector issuer was not read exactly once")
		}
	}
}
func TestContinuationBundledConnectorRootRefusalLeavesInputUnchanged(t *testing.T) {
	for _, mode := range []string{"missing-connector", "invalid-connector", "foreign-mount", "foreign-root"} {
		t.Run(mode, func(t *testing.T) {
			f := newContinuationBaoFixture(t, mode)
			input := f.input()
			input.Public = &contracts.InstallerPublicSettings{Federation: &contracts.InstallerFederationSettings{}}
			if mode == "foreign-mount" {
				input.Public.Federation.ConnectorPKIMount = "foreign"
			}
			if mode == "foreign-root" {
				input.Public.Federation.ConnectorIssuerRootsPEM = f.issuer
			}
			before, _ := json.Marshal(input)
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			p, err := resolveInstallerContinuationKeyServiceWithOpen(ctx, f.base.files, &input, f.original(t), f.base.config, f.open)
			if p != nil {
				p.Close()
			}
			after, _ := json.Marshal(input)
			if mode == "foreign-mount" && f.opens != 0 {
				t.Fatal("invalid fixed mount reached setup login")
			}
			if err == nil || !reflect.DeepEqual(before, after) {
				t.Fatal("changed/unknown selected issuer accepted or mutated input")
			}
		})
	}
}
