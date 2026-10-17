package postgres

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

func TestInitialSQLMaterialReconstructsOriginalPrivateState(t *testing.T) {
	install := "11111111-1111-4111-8111-111111111111"
	request := "22222222-2222-4222-8222-222222222222"
	m, err := NewInitialSQLMaterial(install, request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	retained, err := contracts.DecodeInitialSQLMaterial(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	after := before.Add(15 * time.Minute)
	original, err := BindInitialSQLMaterial(m, install, request, before, after)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := BindInitialSQLMaterial(retained, install, request, before, after)
	if err != nil {
		t.Fatal(err)
	}
	a, err := EncodeInitialSQLCredentials(original, artifact.Digest{2})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(a)
	b, err := EncodeInitialSQLCredentials(replay, artifact.Digest{2})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b)
	if !bytes.Equal(a, b) || !replay.NotAfter.Equal(after) {
		t.Fatal("reconstruction changed secret or original expired interval")
	}
	for _, changed := range []contracts.InitialSQLMaterial{func() contracts.InitialSQLMaterial { x := m; x.RequestID = install; return x }(), func() contracts.InitialSQLMaterial { x := m; x.AuditPassword = x.PreparationPassword; return x }(), func() contracts.InitialSQLMaterial { x := m; x.Format = "other"; return x }()} {
		if _, err = BindInitialSQLMaterial(changed, install, request, before, after); err == nil {
			t.Fatal("invalid private material accepted")
		}
	}
	if _, err = BindInitialSQLMaterial(m, install, request, before, after.Add(time.Second)); err == nil {
		t.Fatal("changed finite interval accepted")
	}
	for _, printed := range []string{fmt.Sprint(m), fmt.Sprintf("%#v", m), fmt.Sprint(&m)} {
		if strings.Contains(printed, m.PreparationPassword) || strings.Contains(printed, m.AuditPassword) || strings.Contains(printed, m.ActivationPassword) {
			t.Fatal("formatting exposed private material")
		}
	}
}
