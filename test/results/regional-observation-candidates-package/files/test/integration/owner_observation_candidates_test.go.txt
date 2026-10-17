package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Actual current SQL, separately scoped roles, encrypted S3 audit and audited
// activation. Initial source/recovery/Pod proof and this private CA are fixture
// authorities; no installed readiness or native routing is claimed here.
func TestOwnerObservationCandidatesWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		path = os.Getenv("ASSERVAT_FLEET_FIXTURES")
	}
	if path == "" {
		t.Skip("owned SQL/S3 fixture required")
	}
	raw, e := os.ReadFile(path)
	var f fixture
	if e != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, end := context.WithTimeout(context.Background(), 90*time.Second)
	defer end()
	ca, key := connectorSQLCA(t)
	pool := value.OwnerPool{InstallationID: custodyID(), ClusterID: custodyID(), IssuerEpoch: custodyID(), Namespace: "hub", NamespaceUID: custodyID(), Service: "owner", ServiceUID: custodyID(), Deployment: "owner", DeploymentUID: custodyID(), ServiceAccount: "owner", AccountUID: custodyID(), Port: 8443, NativePort: 8444, NativeBootstrap: value.OwnerBootstrapProfile, NativeCandidateLimit: 17}
	c := value.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{ca.Raw}}
	l := ownerConfigurationLab(t, ctx, f, c)
	s := newContextStartOwnerSQL(t, ctx, l, c, contextStartOwnerIssuer{ca, key})
	if _, e = s.reader.ReadOwnerObservationCandidates(ctx); e == nil {
		t.Fatal("missing accepted configuration authorized candidate read")
	}
	refresh := func() {
		t.Helper()
		if _, e := s.refresh(ctx, 5*time.Second); e != nil {
			t.Fatal(e)
		}
	}
	refresh()
	if v, e := s.reader.ReadOwnerObservationCandidates(ctx); e != nil || !v.Valid(time.Now()) || len(v.Owners) != 0 {
		t.Fatal("complete original empty set", e)
	}
	var enrolled []value.OwnerEnrollment
	pod := custodyID()
	for range 18 {
		req := value.OwnerEnrollmentRequest{Binding: value.OwnerBinding{InstallationID: pool.InstallationID, ClusterID: pool.ClusterID, IssuerEpoch: pool.IssuerEpoch, PodUID: pod, ProcessEpoch: custodyID()}, Usage: "server", CSRDER: connectorSQLCSR(t)}
		cert, e := s.coordinator().Enroll(ctx, req)
		if e != nil {
			t.Fatal("actual original enrollment", e)
		}
		reg, e := s.reader.ReadOwnerRegistration(ctx, cert.Certificate)
		if e != nil {
			t.Fatal("actual current registration", e)
		}
		enrolled = append(enrolled, reg.Enrollment)
		if len(enrolled) == 17 {
			refresh()
			// A larger opted value bound must not silently bless old LIMIT17 output.
			if _, e = s.reader.ReadContextStartOwners(ctx); e == nil {
				t.Fatal("old LIMIT17 reader returned truncated successful opted set")
			}
			got, e := s.reader.ReadOwnerObservationCandidates(ctx)
			if e != nil || !got.Valid(time.Now()) || len(got.Owners) != 17 {
				t.Fatal("complete configured candidate set", e, len(got.Owners))
			}
			for _, v := range enrolled {
				found := false
				for _, b := range got.Owners {
					if b == v.Binding {
						found = true
					}
				}
				if !found {
					t.Fatal("same-Pod process identity was collapsed")
				}
			}
		}
	}
	refresh()
	if _, e = s.reader.ReadOwnerObservationCandidates(ctx); e == nil {
		t.Fatal("configured limit-plus-one overflow returned success")
	}
	if _, e = s.reader.ReadContextStartOwners(ctx); e == nil {
		t.Fatal("old LIMIT17 reader returned truncated18-process population")
	}
	for _, v := range enrolled[16:] {
		refresh()
		if e = s.cleanup.RetireOwnerEnrollment(ctx, v); e != nil {
			t.Fatal("exact original retirement", e)
		}
	}
	refresh()
	old, e := s.reader.ReadContextStartOwners(ctx)
	if e != nil || len(old.Owners) != 16 {
		t.Fatal("old complete sixteen-entry behavior changed", e)
	}
	current, e := s.reader.ReadOwnerObservationCandidates(ctx)
	if e != nil || len(current.Owners) != 16 {
		t.Fatal("current set included retired process", e)
	}
	t.Run("original-current-source-expires", func(t *testing.T) {
		o, e := s.refresh(ctx, 150*time.Millisecond)
		if e != nil {
			t.Fatal(e)
		}
		timer := time.NewTimer(time.Until(o.FreshUntil) + time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if _, e = s.reader.ReadOwnerObservationCandidates(ctx); e == nil {
			t.Fatal("candidate read renewed expired source")
		}
	})
	refresh()
	if e = l.writer.FenceOwnerConfiguration(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = s.reader.ReadOwnerObservationCandidates(ctx); e == nil {
		t.Fatal("configuration fence returned complete candidates")
	}
	t.Log("separate configured observation reader and old fixed16 overflow; exact17 same-Pod processes retained,18 denied, retired leaves excluded; synthetic initial source/recovery/native proof")
}
