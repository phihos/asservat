package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	wire "asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

type apiTrustFunc func(context.Context) (value.APIContextWorkTrust, error)

func (f apiTrustFunc) APIContextWorkTrust(c context.Context) (value.APIContextWorkTrust, error) {
	return f(c)
}
func apiWorkFixture(t *testing.T) (value.APIContextWork, value.APIContextReceiver, value.APIContextWorkTrust, ed25519.PrivateKey, *time.Time) {
	t.Helper()
	id := func(n string) string { return "00000000-0000-4000-8000-0000000000" + n }
	now := time.Now().UTC().Truncate(time.Microsecond)
	hub := value.OwnerBinding{InstallationID: id("01"), ClusterID: id("02"), IssuerEpoch: id("03"), PodUID: id("04"), ProcessEpoch: id("05")}
	conn := value.ConnectorProcessIdentity{Binding: value.PeerBinding{InstallationID: hub.InstallationID, ClusterID: id("06"), IssuerEpoch: hub.IssuerEpoch, PeerID: id("07"), Role: value.ConnectorPeer}, PodUID: id("08"), ProcessEpoch: id("09")}
	channel := value.APIContextChannel{RootID: id("10"), ExchangeID: id("11"), Challenge: id("12"), Hub: hub, Connector: conn, ConnectorLeaf: artifact.Digest{1}, Executor: value.APIContextExecutor{NamespaceUID: id("13"), AccountUID: id("14"), PodUID: conn.PodUID, ProcessEpoch: id("15"), StartupDigest: artifact.Digest{2}, ImageDigest: artifact.Digest{3}}}
	work := value.APIContextWork{Channel: channel, CaptureID: id("16"), AttemptID: id("17"), Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "actor", ClientID: "console", Kind: identity.Human}, Target: authorization.Target{ClusterID: conn.Binding.ClusterID, NamespaceUID: id("18"), WorkloadUID: id("19"), PodUID: id("20")}, ScopeDigest: artifact.Digest{4}, ExpectationDigest: artifact.Digest{5}, IntentDigest: artifact.Digest{6}, BudgetDigest: artifact.Digest{7}, Capability: identity.Revision{UID: "capability", Generation: 1, Digest: [32]byte{8}}, ProjectionDigest: artifact.Digest{9}, IssuedAt: now, NotAfter: now.Add(5 * time.Second)}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	trust := value.APIContextWorkTrust{RootID: channel.RootID, InstallationID: hub.InstallationID, ClusterID: conn.Binding.ClusterID, IssuerEpoch: hub.IssuerEpoch, Trust: value.WorkTrust{Revision: identity.Revision{UID: "work-source", Generation: 1, Digest: [32]byte{10}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Keys: []value.WorkKey{{ID: "current", ClusterID: conn.Binding.ClusterID, IssuerEpoch: hub.IssuerEpoch, PublicKey: pub, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}}}
	receiver := value.APIContextReceiver{Channel: channel, ObservedAt: now, ValidUntil: work.NotAfter}
	if !work.Valid(now) || !receiver.Valid(now) || !trust.Valid(now) {
		t.Fatal("fixture invalid")
	}
	return work, receiver, trust, key, &now
}
func apiSignatures(t *testing.T, trust apiTrustFunc, key ed25519.PrivateKey, now *time.Time) *APIContextWorkSignatures {
	t.Helper()
	s, e := NewAPIContextWorkSignatures(trust, "current", func(context.Context) crypto.Signer { return key }, func() time.Time { return *now })
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestAPIContextWorkMaximumAndRoundtrip(t *testing.T) {
	w, r, trust, key, now := apiWorkFixture(t)
	w.Actor.Issuer = strings.Repeat(`"`, 2048)
	w.Actor.Subject = strings.Repeat(`\`, 256)
	w.Actor.ClientID = strings.Repeat("&", 256)
	w.Capability.UID = strings.Repeat(`"`, 64)
	w.Capability.Generation = 2147483647
	w.Target.NamespaceUID = strings.Repeat(`"`, 64)
	w.Target.WorkloadUID = strings.Repeat(`\`, 64)
	w.Target.PodUID = strings.Repeat(`"`, 64)
	s := apiSignatures(t, func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }, key, now)
	encoded, e := s.SignAPIContextWork(context.Background(), w)
	if e != nil {
		t.Fatal(e)
	}
	if len(encoded) > wire.APIContextSignedWorkBytes {
		t.Fatal("signed max exceeds cap")
	}
	got, e := s.VerifyAPIContextWork(context.Background(), encoded, r)
	if e != nil || got.Work != w || !got.ValidUntil.Equal(w.NotAfter) {
		t.Fatalf("roundtrip: %v", e)
	}
	t.Logf("maximum signed first-profile work: %d bytes", len(encoded))
	verifier, e := NewAPIContextWorkSignatures(s.trust, "", nil, s.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = verifier.VerifyAPIContextWork(context.Background(), encoded, r); e != nil {
		t.Fatal("verify-only composition rejected")
	}
	if _, e = verifier.SignAPIContextWork(context.Background(), w); e == nil {
		t.Fatal("verify-only signed")
	}
}
func TestAPIContextWorkRejectsSignedProfileAndChannelConfusion(t *testing.T) {
	mutations := map[string]func(*wire.APIContextWork){
		"class":               func(d *wire.APIContextWork) { d.ExecutionClass = "node" },
		"action":              func(d *wire.APIContextWork) { d.ActionID = "exec" },
		"format":              func(d *wire.APIContextWork) { d.Format = "internal-work/v1" },
		"purpose":             func(d *wire.APIContextWork) { d.Purpose = "read" },
		"bytes":               func(d *wire.APIContextWork) { d.NativeBytes++ },
		"hub":                 func(d *wire.APIContextWork) { d.Channel.Hub.ProcessEpoch = d.CaptureID },
		"connector":           func(d *wire.APIContextWork) { d.Channel.Connector.ProcessEpoch = d.CaptureID },
		"executor":            func(d *wire.APIContextWork) { d.Channel.Executor.ProcessEpoch = d.CaptureID },
		"leaf":                func(d *wire.APIContextWork) { d.Channel.Connector.LeafDigest = strings.Repeat("b", 64) },
		"exchange":            func(d *wire.APIContextWork) { d.Channel.ExchangeID = d.CaptureID },
		"challenge":           func(d *wire.APIContextWork) { d.Channel.Challenge = d.CaptureID },
		"cluster":             func(d *wire.APIContextWork) { d.Target.ClusterID = d.CaptureID },
		"zero-scope":          func(d *wire.APIContextWork) { d.ScopeDigest = strings.Repeat("0", 64) },
		"noncanonical-digest": func(d *wire.APIContextWork) { d.IntentDigest = strings.ToUpper(strings.Repeat("ab", 32)) },
		"kind":                func(d *wire.APIContextWork) { d.Actor.Kind = "workload" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			w, r, trust, key, now := apiWorkFixture(t)
			d := apiContextWire(w)
			mutate(&d)
			b, e := wire.EncodeAPIContextWork(d)
			if e != nil {
				t.Fatal(e)
			}
			signed := signWork(t, b, key, jwa.EdDSAEd25519(), map[string]any{"typ": APIContextWorkType})
			s := apiSignatures(t, func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }, key, now)
			if _, e = s.VerifyAPIContextWork(context.Background(), signed, r); e == nil {
				t.Fatal("wrong signed profile accepted")
			}
		})
	}
}
func TestAPIContextWorkRejectsWrongHeaderAndUnclosedPayload(t *testing.T) {
	w, r, trust, key, now := apiWorkFixture(t)
	b, e := wire.EncodeAPIContextWork(apiContextWire(w))
	if e != nil {
		t.Fatal(e)
	}
	s := apiSignatures(t, func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }, key, now)
	for name, payload := range map[string][]byte{"alias": bytes.Replace(b, []byte(`"captureId"`), []byte(`"CaptureId"`), 1), "unknown": append([]byte(`{"token":"forbidden",`), b[1:]...), "duplicate": append([]byte(`{"format":"api-context-work/v1",`), b[1:]...), "space": append([]byte(" "), b...)} {
		t.Run(name, func(t *testing.T) {
			signed := signWork(t, payload, key, jwa.EdDSAEd25519(), map[string]any{"typ": APIContextWorkType})
			if _, e := s.VerifyAPIContextWork(context.Background(), signed, r); e == nil {
				t.Fatal("unclosed payload accepted")
			}
		})
	}
	for _, header := range []map[string]any{{"typ": WorkType}, {"typ": APIContextWorkType, "kid": "other"}, {"typ": APIContextWorkType, "jku": "https://outside.invalid"}} {
		signed := signWork(t, b, key, jwa.EdDSAEd25519(), header)
		if _, e := s.VerifyAPIContextWork(context.Background(), signed, r); e == nil {
			t.Fatal("wrong header accepted")
		}
	}
	var zero APIContextWorkSignatures
	if _, e := zero.VerifyAPIContextWork(context.Background(), b, r); e == nil {
		t.Fatal("zero verifier accepted")
	}
	// Confirm this codec exposes no claim-bearing groups or address fields.
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		t.Fatal("wire")
	}
	if doc["groups"] != nil || doc["url"] != nil {
		t.Fatal("unexpected delegated credential")
	}
}
func TestAPIContextWorkKeepsFirstTrustDeadlineThroughFinalRead(t *testing.T) {
	for _, sign := range []bool{false, true} {
		t.Run(map[bool]string{false: "verify", true: "sign"}[sign], func(t *testing.T) {
			w, r, trust, key, now := apiWorkFixture(t)
			good := apiSignatures(t, func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }, key, now)
			b, e := good.SignAPIContextWork(context.Background(), w)
			if e != nil {
				t.Fatal(e)
			}
			firstUntil := now.Add(time.Second)
			calls := 0
			s := apiSignatures(t, func(ctx context.Context) (value.APIContextWorkTrust, error) {
				calls++
				copy := trust
				if calls == 1 {
					copy.Trust.FreshUntil = firstUntil
				} else {
					if d, ok := ctx.Deadline(); !ok || d.After(firstUntil) {
						t.Error("final read detached from first observation")
					}
					*now = firstUntil
				}
				return copy, nil
			}, key, now)
			if sign {
				_, e = s.SignAPIContextWork(context.Background(), w)
			} else {
				_, e = s.VerifyAPIContextWork(context.Background(), b, r)
			}
			if e == nil || calls != 2 {
				t.Fatalf("final read renewed original trust: calls=%d err=%v", calls, e)
			}
		})
	}
}

func TestAPIContextWorkClampsShorterOriginalPeerProof(t *testing.T) {
	w, receiver, trust, key, now := apiWorkFixture(t)
	s := apiSignatures(t, func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }, key, now)
	encoded, e := s.SignAPIContextWork(context.Background(), w)
	if e != nil {
		t.Fatal(e)
	}
	receiver.ValidUntil = receiver.ObservedAt.Add(3 * time.Second)
	checked, e := s.VerifyAPIContextWork(context.Background(), encoded, receiver)
	if e != nil || !checked.ValidUntil.Equal(receiver.ValidUntil) {
		t.Fatalf("overlapping original intervals were rejected or widened: %v", e)
	}
	*now = receiver.ValidUntil
	if _, e = s.VerifyAPIContextWork(context.Background(), encoded, receiver); e == nil {
		t.Fatal("expired original peer observation was refreshed")
	}
}
