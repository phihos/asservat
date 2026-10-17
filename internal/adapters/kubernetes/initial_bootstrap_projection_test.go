package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Original projection construction is passive provenance. Active first creation
// separately checks current guards; completed handover may have retired staging.
func TestInitialBootstrapProjectionSurvivesSetupRetirementWithoutNewPins(t *testing.T) {
	d, s := bootstrapStateFixture(t)
	d.Image = "example.invalid/asservat@sha256:" + strings.Repeat("a", 64)
	original, e := bootstrapProjectionValue(d, s)
	if e != nil {
		t.Fatal(e)
	}
	expired := cloneBootstrapState(t, s)
	expired.Manager.StartedAt = time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	expired.Manager.Until = expired.Manager.StartedAt.Add(30 * time.Minute)
	at := expired.Manager.Until.Add(time.Minute)
	expired.Manager.Closing = &contracts.InitialBootstrapClose{OperationID: ownerID(81), StartedAt: at, Until: at.Add(30 * time.Second)}
	retired := at.Add(time.Second)
	expired.Manager.RetiredAt = &retired
	expired.Retired = true
	expired.Material = nil
	expired.Passwords = contracts.InitialBootstrapPasswords{History: s.Passwords.History}
	got, e := bootstrapProjectionValue(d, expired)
	if e != nil || !equalJSON(original, got) {
		t.Fatal("passive projection changed with setup retirement")
	}
	if got.Plan.SchemaInitialization != contracts.InitialSchemaProtocol || got.Plan.HistoryManager == nil || *got.Plan.HistoryManager != *s.Manager.Receipt || got.Plan.InstallationID != s.InstallationID || got.Plan.RequestID != s.RequestID {
		t.Fatal("original schema/manager/installation pins lost")
	}
	raw, e := json.Marshal(got)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{s.Passwords.Manager, s.Passwords.Preparation, s.Passwords.Audit, s.Passwords.Activation, s.Passwords.History, s.Material.IssuerToken, s.Material.Storage.SecretAccessKey} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private source material appeared in public projection")
		}
	}
	// A replacement resource remains a different projection, never an equivalent
	// current observation of the original immutable startup input.
	changed := cloneBootstrapState(t, s)
	changed.Creates[3].Receipt.UID = ownerID(90)
	replacement, e := bootstrapProjectionValue(d, changed)
	if e != nil || equalJSON(original, replacement) {
		t.Fatal("replacement policy collapsed into original provenance")
	}
}

func TestInitialBootstrapProjectionReceiptChecksWholeImmutableObject(t *testing.T) {
	d, s := bootstrapStateFixture(t)
	projection, e := bootstrapProjectionValue(d, s)
	if e != nil {
		t.Fatal(e)
	}
	wanted, e := bootstrapProjectionObject(d, s, projection)
	if e != nil {
		t.Fatal(e)
	}
	got := wanted.DeepCopy()
	got.UID = types.UID(s.Projection.UID)
	got.ResourceVersion = s.Creates[7].Receipt.ResourceVersion
	got.CreationTimestamp = meta.Now()
	if !bootstrapObjectMatches(wanted, got) {
		t.Fatal("exact original public projection rejected")
	}
	for label, edit := range map[string]func(){
		"operation": func() { got.Annotations["asservat.io/bootstrap-operation-id"] = ownerID(91) },
		"extra-key": func() { got.Data["unrequested"] = "value" },
		"namespace": func() { got.Namespace = "elsewhere" },
		"mutable":   func() { *got.Immutable = false },
		"owner":     func() { got.OwnerReferences = []meta.OwnerReference{{Name: "foreign", UID: types.UID(ownerID(92))}} },
	} {
		t.Run(label, func(t *testing.T) {
			got = wanted.DeepCopy()
			got.UID = types.UID(s.Projection.UID)
			got.ResourceVersion = "1"
			edit()
			if bootstrapObjectMatches(wanted, got) {
				t.Fatal("changed projection admitted")
			}
		})
	}
}
