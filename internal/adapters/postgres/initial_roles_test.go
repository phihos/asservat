package postgres

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestInitialSQLCredentialEntropyScopeAndRedaction(t *testing.T) {
	p, err := NewInitialSQLCredentials("11111111-1111-4111-8111-111111111111", time.Now())
	if err != nil || !p.valid() {
		t.Fatal(err)
	}
	for _, l := range p.logins() {
		b, err := base64.RawURLEncoding.DecodeString(l.Password)
		if err != nil || len(b) != 32 || len(l.Username) > 63 {
			t.Fatal("invalid generated credential")
		}
		for _, printed := range []string{fmt.Sprint(p), fmt.Sprintf("%+v", p), fmt.Sprintf("%#v", p), fmt.Sprint(l), fmt.Sprintf("%#v", l)} {
			if strings.Contains(printed, l.Password) {
				t.Fatal("credential logging leak")
			}
		}
		a, err := initialPasswordVerifier(l)
		if err != nil {
			t.Fatal(err)
		}
		b64, err := initialPasswordVerifier(l)
		if err != nil || a == b64 || !strings.HasPrefix(a, "SCRAM-SHA-256$4096:") || strings.Contains(a, l.Password) || strings.ContainsAny(a, "'\\\r\n") {
			t.Fatal("unsafe verifier")
		}
	}
	for i, role := range []string{"prepare", "audit", "activate"} {
		name, err := InitialSQLRoleName(p.InstallationID, role)
		if err != nil || name != p.logins()[i].Username {
			t.Fatal("runtime role does not match provisioned scope")
		}
	}
	for _, role := range []string{"postgres", "", "audit;SET ROLE postgres"} {
		if _, err := InitialSQLRoleName(p.InstallationID, role); err == nil {
			t.Fatal("invalid role purpose")
		}
	}
	if _, err := InitialSQLRoleName("foreign", "prepare"); err == nil {
		t.Fatal("invalid installation")
	}
	for _, change := range []func(*InitialSQLCredentials){
		func(p *InitialSQLCredentials) { p.Activation = p.Preparation },
		func(p *InitialSQLCredentials) { p.Audit.Password = p.Preparation.Password },
		func(p *InitialSQLCredentials) { p.Preparation.Username = "postgres" },
		func(p *InitialSQLCredentials) { p.NotAfter = p.NotAfter.Add(time.Minute) },
		func(p *InitialSQLCredentials) { p.Preparation.Password = "invalid-sensitive-password" },
	} {
		bad := p
		change(&bad)
		if bad.valid() {
			t.Fatal("invalid secret plan accepted")
		}
	}
	if _, err := initialPasswordVerifier(InitialSQLLogin{Username: "invalid", Password: strings.Repeat("'", 43)}); err == nil || strings.Contains(err.Error(), "'") {
		t.Fatal("invalid password handling", err)
	}
}

func TestInitialSQLCredentialStateScopeAndClosedDecoding(t *testing.T) {
	p, err := NewInitialSQLCredentials("11111111-1111-4111-8111-111111111111", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	digest := artifact.Digest{1}
	raw, err := EncodeInitialSQLCredentials(p, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	got, err := DecodeInitialSQLCredentials(raw, p.InstallationID, digest)
	if err != nil || got.InstallationID != p.InstallationID || got.Preparation != p.Preparation || got.Audit != p.Audit || got.Activation != p.Activation || !got.NotBefore.Equal(p.NotBefore) || !got.NotAfter.Equal(p.NotAfter) {
		t.Fatal("immutable secret did not round trip")
	}
	for _, bad := range [][]byte{
		[]byte(strings.Replace(string(raw), `"format":`, `"extra":true,"format":`, 1)),
		[]byte(strings.Replace(string(raw), `"format":`, `"format":"duplicate","format":`, 1)),
		[]byte(strings.Replace(string(raw), `"format":`, `"Format":`, 1)),
		append(append([]byte(nil), raw...), []byte(` {}`)...),
		[]byte(strings.Replace(string(raw), p.Preparation.Password, "invalid", 1)),
		[]byte(strings.Repeat(" ", 4097)),
	} {
		if _, err := DecodeInitialSQLCredentials(bad, p.InstallationID, digest); err == nil {
			t.Fatal("invalid secret accepted")
		}
		clear(bad)
	}
	if _, err = DecodeInitialSQLCredentials(raw, p.InstallationID, artifact.Digest{2}); err == nil {
		t.Fatal("different plan accepted")
	}
	if _, err = DecodeInitialSQLCredentials(raw, "22222222-2222-4222-8222-222222222222", digest); err == nil {
		t.Fatal("different installation accepted")
	}
}
