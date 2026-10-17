package providerconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestConfigurationSetupBindingPreservesCompleteIntegerInputs(t *testing.T) {
	in, selection, account, now := configurationProviderRecipeFixture(t)
	recipe, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil {
		t.Fatal(err)
	}
	in.FleetGuard.PolicyGeneration = 1 << 53
	first, err := configurationSetupBinding(in, recipe.Profile)
	if err != nil {
		t.Fatal(err)
	}
	check := ConfigurationSetupCheck{binding: first, observedAt: now, until: now.Add(time.Second)} // synthetic check for codec boundary only
	if !check.Matches(in, recipe.Profile, now) {
		t.Fatal("original complete input lost")
	}
	in.FleetGuard.PolicyGeneration++
	second, err := configurationSetupBinding(in, recipe.Profile)
	if err != nil || first == second || check.Matches(in, recipe.Profile, now) {
		t.Fatal("distinct int64 generation aliased the original provider check", err)
	}
	// Recipe scope intentionally excludes guard observation details; preserve
	// its existing golden bytes while the whole-input check remains exact.
	again, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil || again.Profile != recipe.Profile {
		t.Fatal("complete binding changed auth recipe identity", err)
	}
}

func configurationSetupLargeCA(t *testing.T, serial int64, padding int, now time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 149}, Value: bytes.Repeat([]byte{1}, padding)}}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestConfigurationSetupBindingUsesDeploymentLimitRatherThanRecipeLimit(t *testing.T) {
	in, selection, account, now := configurationProviderRecipeFixture(t)
	in.Kubernetes.Roots = [][]byte{configurationSetupLargeCA(t, 1, 10000, now), configurationSetupLargeCA(t, 2, 10000, now)}
	in.Postgres.Roots = [][]byte{configurationSetupLargeCA(t, 3, 14000, now), configurationSetupLargeCA(t, 4, 14000, now)}
	recipe, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil {
		t.Fatal("qualified provider bounds rejected by actual pure validator", err)
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) <= 64<<10 || len(raw) >= contracts.OwnerDeploymentMaxBytes {
		t.Fatal("fixture did not cross only the recipe helper limit", len(raw), err)
	}
	if _, err = configurationSetupBinding(in, recipe.Profile); err != nil {
		t.Fatal("whole deployment accidentally inherited recipe 64 KiB cap", err)
	}
	// Exact maximum arithmetic is checked at the actual encoder boundary. This
	// extra string is deliberately malformed provider input; only the size helper
	// is under test, and no successful SetupCheck can be produced from it.
	before := len(raw)
	in.FleetGuard.Name = strings.Repeat("x", contracts.OwnerDeploymentMaxBytes-before)
	raw, err = json.Marshal(in)
	if err != nil || len(raw) != contracts.OwnerDeploymentMaxBytes {
		t.Fatal("maximum boundary fixture drift", len(raw), err)
	}
	if _, err = configurationSetupBinding(in, recipe.Profile); err != nil {
		t.Fatal("exact deployment maximum rejected", err)
	}
	in.FleetGuard.Name += "x"
	if _, err = configurationSetupBinding(in, recipe.Profile); err == nil {
		t.Fatal("oversized deployment binding accepted")
	}
}
