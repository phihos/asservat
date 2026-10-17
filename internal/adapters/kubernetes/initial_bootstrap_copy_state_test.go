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

func bootstrapCopyStateFixture(t *testing.T) (contracts.InitialBootstrap, *meta.PartialObjectMetadata, *InitialBootstrapPassiveRead) {
	t.Helper()
	d := bootstrapAdmissionFixture(t)
	d.Format = contracts.InitialBootstrapCopyClosureFormat
	_, state := bootstrapStateFixture(t)
	state.Prelude.CopyMarker = &contracts.WorkerObjectReference{Name: bootstrapNames(d).copyMarker, UID: ownerID(19)}
	state.DesiredDigest = bootstrapDigest(d)
	c, err := bootstrapProjectionValue(d, state)
	if err != nil {
		t.Fatal(err)
	}
	state.PassiveHistory = &contracts.InitialBootstrapCreate{Step: "passive-history", OperationID: ownerID(81), Receipt: &contracts.InitialPreparationReceipt{UID: ownerID(82), ResourceVersion: "1"}}
	now := time.Now().UTC().Truncate(time.Microsecond)
	at := now.Add(-10 * time.Second)
	retired := contracts.InitialBootstrapManagerRetirement{OperationID: ownerID(83), Manager: *state.Manager.Receipt, StartedAt: at.Add(-time.Second), Until: at.Add(29 * time.Second), RetiredAt: at}
	obs, err := bootstrapObservationValue(d, state, c)
	if err != nil {
		t.Fatal(err)
	}
	p := &InitialBootstrapPassiveRead{ManagerRetired: true, ManagerRetirement: &retired, ValidUntil: now.Add(5 * time.Second), Bundle: contracts.InitialBootstrapPassiveBundle{Seed: contracts.WorkerObjectReference{Name: bootstrapNames(d).seed, UID: state.SeedUID}, Configuration: c, Observation: obs}}
	claim := contracts.InitialBootstrapCopyClaim{Format: contracts.InitialBootstrapCopyClaimFormat, OperationID: ownerID(84), InstallationID: state.InstallationID, RequestID: state.RequestID, Namespace: state.Prelude.Namespace, Seed: p.Bundle.Seed, Projection: *state.Projection, History: contracts.WorkerObjectReference{Name: bootstrapNames(d).passiveHistory, UID: ownerID(82)}, Root: contracts.WorkerObjectReference{Name: bootstrapNames(d).root, UID: ownerID(85)}, ManagerCloseID: retired.OperationID, ManagerRetiredAt: at, ActivatedClaimID: ownerID(86), StartedAt: at, Until: at.Add(contracts.InitialBootstrapCopyCleanupDuration), SQL: *c.SQLMaterial, Provider: c.Providers.Material, PolicyOperationID: ownerID(87), BindingOperationID: ownerID(88)}
	if !bootstrapCopyClaimValid(d, claim) {
		t.Fatal("invalid synthetic closure claim")
	}
	m := &meta.PartialObjectMetadata{ObjectMeta: meta.ObjectMeta{Name: bootstrapNames(d).seed, Namespace: d.BootstrapNamespace, UID: types.UID(state.SeedUID), ResourceVersion: "7", Annotations: map[string]string{}}}
	put := func(k string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		m.Annotations[k] = string(b)
	}
	put(bootstrapCopyClaimAnnotation, claim)
	put(initialBootstrapPassiveAnnotation, bootstrapPassiveLocator(d, state))
	m.Annotations[bootstrapCopyPolicyStartedAnnotation] = at.Add(time.Second).Format(time.RFC3339Nano)
	m.Annotations[bootstrapCopyBindingStartedAnnotation] = at.Add(3 * time.Second).Format(time.RFC3339Nano)
	put(bootstrapCopyPolicyAnnotation, contracts.InitialBootstrapCopyReceipt{UID: ownerID(89), ResourceVersion: "2", ObservedAt: at.Add(2 * time.Second)})
	put(bootstrapCopyBindingAnnotation, contracts.InitialBootstrapCopyReceipt{UID: ownerID(90), ResourceVersion: "3", ObservedAt: at.Add(4 * time.Second)})
	for i, pair := range []struct {
		ref          contracts.WorkerObjectReference
		mark, remove string
	}{{claim.SQL, bootstrapCopySQLMarkedAnnotation, bootstrapCopySQLAnnotation}, {claim.Provider, bootstrapCopyProviderMarkedAnnotation, bootstrapCopyProviderAnnotation}} {
		put(pair.mark, contracts.InitialBootstrapCopyReceipt{UID: pair.ref.UID, ResourceVersion: "6", ObservedAt: at.Add(time.Duration(5+i*2) * time.Second)})
		put(pair.remove, contracts.InitialBootstrapCopyReceipt{UID: pair.ref.UID, ResourceVersion: "6", ObservedAt: at.Add(time.Duration(6+i*2) * time.Second)})
	}
	m.Annotations[bootstrapCopyCompleteAnnotation] = at.Add(9 * time.Second).Format(time.RFC3339Nano)
	return d, m, p
}
func TestInitialBootstrapCopyStateRequiresOriginalPositiveReceipts(t *testing.T) {
	d, m, p := bootstrapCopyStateFixture(t)
	got, err := bootstrapReadCopyState(d, m, p)
	if err != nil || !got.CopiesClosed() {
		t.Fatal("original bounded positive state", err)
	}
	for name, edit := range map[string]func(*meta.PartialObjectMetadata, *InitialBootstrapPassiveRead){
		"missing-manager": func(_ *meta.PartialObjectMetadata, p *InitialBootstrapPassiveRead) { p.ManagerRetirement = nil },
		"missing-copy-mark": func(m *meta.PartialObjectMetadata, _ *InitialBootstrapPassiveRead) {
			delete(m.Annotations, bootstrapCopySQLMarkedAnnotation)
		},
		"missing-positive-removal": func(m *meta.PartialObjectMetadata, _ *InitialBootstrapPassiveRead) {
			delete(m.Annotations, bootstrapCopySQLAnnotation)
		},
		"missing-original-create": func(m *meta.PartialObjectMetadata, _ *InitialBootstrapPassiveRead) {
			delete(m.Annotations, bootstrapCopyPolicyStartedAnnotation)
		},
		"missing-guard": func(m *meta.PartialObjectMetadata, _ *InitialBootstrapPassiveRead) {
			delete(m.Annotations, bootstrapCopyBindingAnnotation)
		},
		"changed-public-copy": func(_ *meta.PartialObjectMetadata, p *InitialBootstrapPassiveRead) {
			x := *p.Bundle.Configuration.SQLMaterial
			x.UID = ownerID(99)
			p.Bundle.Configuration.SQLMaterial = &x
		},
		"replaced-seed": func(_ *meta.PartialObjectMetadata, p *InitialBootstrapPassiveRead) { p.Bundle.Seed.UID = ownerID(99) },
		"future-completion": func(m *meta.PartialObjectMetadata, _ *InitialBootstrapPassiveRead) {
			m.Annotations[bootstrapCopyCompleteAnnotation] = time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour).Format(time.RFC3339Nano)
		},
		"malformed-claim": func(m *meta.PartialObjectMetadata, _ *InitialBootstrapPassiveRead) {
			m.Annotations[bootstrapCopyClaimAnnotation] = `{"unknown":true}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			d, m, p := bootstrapCopyStateFixture(t)
			edit(m, p)
			if _, err := bootstrapReadCopyState(d, m, p); err == nil {
				t.Fatal("missing/replaced positive identity accepted")
			}
		})
	}
}
func TestInitialBootstrapCopyStateRejectsDeadlineRenewalAndChangedDeleteCAS(t *testing.T) {
	for _, kind := range []string{"renew-interval", "wrong-delete-rv", "alias-guard", "wrong-manager-close", "extra-claim-field"} {
		t.Run(kind, func(t *testing.T) {
			d, m, p := bootstrapCopyStateFixture(t)
			if kind == "wrong-delete-rv" || kind == "alias-guard" {
				key := bootstrapCopySQLAnnotation
				if kind == "alias-guard" {
					key = bootstrapCopyBindingAnnotation
				}
				r, _ := contracts.DecodeInitialBootstrapCopyReceipt(strings.NewReader(m.Annotations[key]))
				if kind == "wrong-delete-rv" {
					r.ResourceVersion = "replacement"
				} else {
					r.UID = ownerID(89)
				}
				b, _ := json.Marshal(r)
				m.Annotations[key] = string(b)
			} else {
				c, _ := contracts.DecodeInitialBootstrapCopyClaim(strings.NewReader(m.Annotations[bootstrapCopyClaimAnnotation]))
				if kind == "renew-interval" {
					c.Until = c.Until.Add(time.Minute)
				}
				if kind == "wrong-manager-close" {
					c.ManagerCloseID = ownerID(99)
				}
				b, _ := json.Marshal(c)
				m.Annotations[bootstrapCopyClaimAnnotation] = string(b)
				if kind == "extra-claim-field" {
					m.Annotations[bootstrapCopyClaimAnnotation] = strings.TrimSuffix(string(b), "}") + `,"renew":true}`
				}
			}
			if _, err := bootstrapReadCopyState(d, m, p); err == nil {
				t.Fatal("original closure/copy CAS changed")
			}
		})
	}
}
func TestInitialBootstrapV3DoesNotRewriteLegacyGuardOrPrelude(t *testing.T) {
	d := bootstrapAdmissionFixture(t)
	for _, format := range []string{contracts.InitialBootstrapFormat, contracts.InitialBootstrapPassiveFormat} {
		d.Format = format
		p, _, err := InitialBootstrapAdmission(d)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(p)
		if strings.Contains(string(b), "bootstrap-copy-") || strings.Contains(string(b), "copy-tombstone") {
			t.Fatal("new closure changed old guard")
		}
		role := bootstrapProbeRole(d)
		if len(role.Rules) != 1 || len(role.Rules[0].ResourceNames) != 2 {
			t.Fatal("legacy probe rights changed")
		}
	}
	_, state := bootstrapStateFixture(t)
	body, _ := json.Marshal(state.Prelude)
	if strings.Contains(string(body), "copyMarker") {
		t.Fatal("legacy bytes gained optional marker")
	}
	d, m, p := bootstrapCopyStateFixture(t)
	v, err := bootstrapReadCopyState(d, m, p)
	if err != nil {
		t.Fatal(err)
	}
	policy, _, err := InitialBootstrapCopyAdmission(d, v.Claim)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range policy.Spec.MatchConditions {
		if strings.Contains(c.Expression, "variables.") {
			t.Fatal("unsupported CEL variable in matching")
		}
	}
	expr := policy.Spec.Validations[0].Expression
	for _, required := range []string{v.Claim.SQL.UID, v.Claim.Provider.UID, v.Claim.OperationID, "oldObject.metadata.uid", "object.data == oldObject.data", "request.operation == 'DELETE'"} {
		if !strings.Contains(expr, required) {
			t.Fatal("missing exact original closure condition", required)
		}
	}
}
