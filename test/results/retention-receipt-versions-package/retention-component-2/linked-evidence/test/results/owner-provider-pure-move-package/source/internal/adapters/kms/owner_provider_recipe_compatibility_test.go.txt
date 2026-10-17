package kms

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

type ownerProviderRecipeGoldenInput struct {
	Name             string
	Now              time.Time
	Input            contracts.OwnerDeployment
	Account          contracts.WorkerObjectReference
	AuditCredentials contracts.WorkerObjectReference
	Mount, Accessor  string
}

// Golden files are original-function output from fixed public inputs and a
// fixed validation instant. They contain no credential or private-key data.
// Regeneration is deliberately absent from the normal test path.
func TestOwnerProviderRecipeMovePreservesOriginalBytes(t *testing.T) {
	directory := filepath.Join("testdata", "owner-provider-recipe-v1")
	raw, err := os.ReadFile(filepath.Join(directory, "inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []ownerProviderRecipeGoldenInput
	if err = json.Unmarshal(raw, &cases); err != nil || len(cases) != 5 {
		t.Fatal("fixed original input corpus", err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			got, err := OwnerProviderRecipeFor(c.Input, c.Mount, c.Accessor, c.Account, c.AuditCredentials, c.Now)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := os.ReadFile(filepath.Join(directory, c.Name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			actual, err := json.Marshal(got)
			if err != nil || !bytes.Equal(actual, bytes.TrimSuffix(expected, []byte("\n"))) {
				t.Fatal("pure move changed original canonical recipe/profile bytes", err)
			}
			var retained OwnerProviderRecipe
			if json.Unmarshal(expected, &retained) != nil || ValidateOwnerProviderAuthentication(c.Input, retained.Profile, c.Now) != nil {
				t.Fatal("original retained profile no longer validates")
			}
		})
	}
}
