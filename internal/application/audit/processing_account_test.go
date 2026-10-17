package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
)

func TestProcessingAccountSurvivesInputRotationAndSeparatesRules(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	other := "22222222-2222-4222-8222-222222222222"
	account := make([]byte, 32)
	account[0] = 9
	a := make([]byte, 32)
	a[0] = 1
	b := make([]byte, 32)
	b[0] = 2
	first, e := NewOperationMAC("first", a, "fixed", account)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	second, e := NewOperationMAC("second", b, "fixed", account)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	x, e := first.ProcessingAccount(id, id, id)
	if e != nil || x == (artifact.Digest{}) {
		t.Fatal(e)
	}
	y, e := second.ProcessingAccount(id, id, id)
	if e != nil || x != y {
		t.Fatal("input key rotation refilled a rule", e)
	}
	for _, values := range [][3]string{{other, id, id}, {id, other, id}, {id, id, other}} {
		z, e := first.ProcessingAccount(values[0], values[1], values[2])
		if e != nil || z == x {
			t.Fatal("rule/installation/root accounts collided", e)
		}
	}
	first.Close()
	if _, e := first.ProcessingAccount(id, id, id); e == nil {
		t.Fatal("retained account signer survived close")
	}
}
