package audit

import (
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestCaptureReasonPrepareBindsOpaqueEnvelopeAndOwnsBytes(t *testing.T) {
	in, mac := captureOperationFixture(t)
	c := *in.Capture
	human := c.Actor
	c.Actor = authorization.PolicyPrincipal(c.RootID, "policy")
	c.Initiator = &human
	e := value.CaptureReasonEnvelope{Format: value.CaptureReasonEnvelopeFormat, KeyReference: []byte("control-key"), WrappedKey: []byte("wrapped"), Ciphertext: bytes.Repeat([]byte{1}, 34)}
	raw, err := EncodeCaptureReasonEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	c.ReasonRef = &value.CaptureReasonRef{ID: c.CaptureID, CiphertextDigest: sha256.Sum256(raw)}
	d, err := mac.CaptureAccount(in.Lifecycle.Policy.InstallationID, c.RootID, c.RootID)
	if err != nil {
		t.Fatal(err)
	}
	a := value.CaptureAuditAccount{RootID: c.RootID, AllocationID: c.RootID, AccountVersion: mac.AccountVersion(), AccountDigest: d, Revision: 1, Records: 10, RetainedSeconds: 3600, Policy: in.Lifecycle.Policy}
	if _, err = PrepareCaptureOperation(c, a, mac, c.CreatedAt.Add(5*time.Second)); err == nil {
		t.Fatal("legacy constructor accepted reason without envelope")
	}
	prepared, err := PrepareCaptureReasonOperation(c, a, mac, c.CreatedAt.Add(5*time.Second), e)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.InputFormat != value.CaptureReasonInputFormat {
		t.Fatal("legacy input domain reused")
	}
	expected := OperationLifecycleDigest(prepared)
	e.Ciphertext[0] ^= 1
	if OperationLifecycleDigest(prepared) != expected {
		t.Fatal("caller changed frozen intent")
	}
	if _, err = PrepareCaptureReasonOperation(c, a, mac, c.CreatedAt.Add(5*time.Second), e); err == nil {
		t.Fatal("ciphertext ref tamper accepted")
	}
	legacy, _ := captureOperationFixture(t)
	encoded, err := EncodeCaptureOperationIntent(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("ReasonRef")) || bytes.Contains(encoded, []byte("ReasonEnvelope")) {
		t.Fatal("absent fields changed legacy encoding")
	}
	// Build the exact pre-reason DTO field order/types, excluding only the two
	// added optional fields. This compares bytes, not JSON semantic equality.
	oldCapture := capturePreReasonDTO(reflect.ValueOf(*legacy.Capture), "ReasonRef", reflect.Value{})
	oldIntent := capturePreReasonDTO(reflect.ValueOf(legacy), "ReasonEnvelope", oldCapture)
	oldBytes, err := captureEncoding(oldIntent.Interface(), 16<<10)
	if err != nil || !bytes.Equal(encoded, oldBytes) {
		t.Fatal("pre-reason legacy byte contract changed")
	}
	var round value.OperationIntent
	if json.Unmarshal(encoded, &round) != nil {
		t.Fatal("legacy decode")
	}
	again, err := EncodeCaptureOperationIntent(round)
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatal("legacy bytes changed")
	}
	if _, err = captureEncoding(bytes.Repeat([]byte{1}, value.CaptureReasonPlainLimit), value.CaptureReasonPlainLimit); err == nil {
		t.Fatal("oversize frame accepted")
	}
}

func capturePreReasonDTO(v reflect.Value, omit string, capture reflect.Value) reflect.Value {
	var fields []reflect.StructField
	var values []reflect.Value
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if field.Name == omit {
			continue
		}
		val := v.Field(i)
		if field.Name == "Capture" && capture.IsValid() {
			val = capture.Addr()
			field.Type = val.Type()
		}
		fields = append(fields, field)
		values = append(values, val)
	}
	out := reflect.New(reflect.StructOf(fields)).Elem()
	for i, val := range values {
		out.Field(i).Set(val)
	}
	return out
}
