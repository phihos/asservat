package audit

import (
	"bytes"
	"testing"
)

func TestCaptureAccountCompartmentMatchesAdmissionAndOwnsItsKey(t *testing.T) {
	const installation = "10000000-0000-4000-8000-000000000001"
	const root = "10000000-0000-4000-8000-000000000002"
	const allocation = "10000000-0000-4000-8000-000000000003"
	key := bytes.Repeat([]byte{7}, 32)
	admission, e := NewOperationMAC("input-v1", bytes.Repeat([]byte{9}, 32), "account-v1", key)
	if e != nil {
		t.Fatal(e)
	}
	defer admission.Close()
	capacity, e := NewCaptureAccounts(installation, "account-v1", key)
	if e != nil {
		t.Fatal(e)
	}
	defer capacity.Close()
	clear(key)
	want, e := admission.CaptureAccount(installation, root, allocation)
	if e != nil {
		t.Fatal(e)
	}
	got, e := capacity.CaptureAccount(root, allocation)
	if e != nil || got != want || capacity.AccountVersion() != admission.AccountVersion() {
		t.Fatal("capacity account differs from exact admission identity")
	}
	other, e := NewCaptureAccounts("10000000-0000-4000-8000-000000000004", "account-v1", bytes.Repeat([]byte{7}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	moved, e := other.CaptureAccount(root, allocation)
	if e != nil || moved == want {
		t.Fatal("installation separation missing")
	}
	capacity.Close()
	if _, e = capacity.CaptureAccount(root, allocation); e == nil {
		t.Fatal("closed account material remained usable")
	}
}
