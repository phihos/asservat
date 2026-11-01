package objectstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

// Test-only clear wrapping lets real Tink/framing run without a provider. It
// confers no runtime key authority and is never selected by product code.
type historyTestKeys struct {
	windowTestKeys
	wraps, unwraps int
}

func (k *historyTestKeys) Seal(ctx context.Context, b, ad []byte) (artifact.SealedKey, error) {
	k.wraps++
	if len(b) > 4096 {
		return artifact.SealedKey{}, fmt.Errorf("payload reached key service")
	}
	return k.windowTestKeys.Seal(ctx, b, ad)
}
func (k *historyTestKeys) Open(ctx context.Context, s artifact.SealedKey, ad []byte) ([]byte, error) {
	k.unwraps++
	return k.windowTestKeys.Open(ctx, s, ad)
}

func historyParametersFixture(t *testing.T) (value.HistoryParameters, value.HistoryExpectation, *auditapp.OperationMAC) {
	t.Helper()
	id := func(n int) string { return fmt.Sprintf("10000000-0000-4000-8000-%012d", n) }
	at := time.Now().UTC().Truncate(time.Microsecond)
	p := value.HistoryParameters{Format: value.HistoryParametersFormat, Target: targets.WorkloadRequest{ClusterID: id(1), Namespace: "payments", Kind: "Deployment", Name: "api"}, NamespaceUID: "namespace", WorkloadUID: "workload", Diagnostic: value.ContextDiagnosticName, RecipeJSON: json.RawMessage(`{"actions":[{"id":"pod-status","kind":"kubernetesSnapshot"}]}`), DependencyJSON: json.RawMessage(`[]`), RequestedSeconds: 120, OriginalEffectiveSeconds: 120, OriginalExecutionDigest: artifact.Digest{7}}
	mac, err := auditapp.NewOperationMAC("input-v1", bytes.Repeat([]byte{1}, 32), "account-v1", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mac.Close)
	s, k, err := app.HistoryParameterKeys(mac, id(2), p)
	if err != nil {
		t.Fatal(err)
	}
	e := value.HistoryExpectation{RootID: id(2), CaptureID: id(3), Registration: artifact.Registration{Location: artifact.Location{ClusterID: id(1), ArtifactID: id(4), AttemptID: id(5)}, StoreID: id(6), AllocationID: id(7), PoolRevision: 1, AllocationRevision: 1, NativeLimit: value.MaxHistoryParameters, AnchorAt: at, WriteUntil: at.Add(time.Minute), ExpiresAt: at.Add(time.Hour), DeleteBy: at.Add(2 * time.Hour)}, SelectorKey: s, SettingsKey: k, MACVersion: mac.AccountVersion(), OriginalExecutionDigest: p.OriginalExecutionDigest}
	return p, e, mac
}

func historyFinalBundle(t *testing.T, e value.HistoryExpectation, b HistoryBundle) (HistoryBundle, artifact.Copies) {
	t.Helper()
	var c artifact.Copies
	for i, body := range b {
		if i == 3 {
			var err error
			body, err = BindHistoryCommit(e, b, c[2])
			if err != nil {
				t.Fatal(err)
			}
			b[3] = body
		}
		c[i] = artifact.CopyReceipt{VersionID: fmt.Sprint(i + 1), ETag: fmt.Sprintf("\"history-%d\"", i), Bytes: int64(len(body)), SHA256: artifact.Digest(sha256.Sum256(body))}
	}
	return b, c
}

func TestHistoryParametersEncryptedRoundTripAndCosts(t *testing.T) {
	for _, size := range []int{0, 32 << 10, 120 << 10} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			p, e, mac := historyParametersFixture(t)
			if size != 0 {
				raw := make([]byte, size/2)
				if _, err := rand.Read(raw); err != nil {
					t.Fatal(err)
				}
				p.RecipeJSON, _ = json.Marshal(map[string]string{"syntheticParameter": fmt.Sprintf("%x", raw)})
				var err error
				e.SelectorKey, e.SettingsKey, err = app.HistoryParameterKeys(mac, e.RootID, p)
				if err != nil {
					t.Fatal(err)
				}
			}
			keys := &historyTestKeys{}
			b, err := SealHistoryParameters(t.Context(), e, p, keys, mac)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Clear()
			if keys.wraps != 3 || keys.unwraps != 0 {
				t.Fatal("not three wrap-only key preparations", keys)
			}
			b, c := historyFinalBundle(t, e, b)
			wire, err := EncodeHistoryBundle(b)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(wire)
			decoded, err := DecodeHistoryBundle(wire)
			if err != nil {
				t.Fatal(err)
			}
			defer decoded.Clear()
			got, err := OpenHistoryParameters(t.Context(), e, c, decoded, keys, mac)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := value.CanonicalHistoryParameters(p)
			actual, _ := value.CanonicalHistoryParameters(got)
			if !bytes.Equal(want, actual) || keys.unwraps != 3 {
				t.Fatal("settings changed or unexpected unwrap count", keys.unwraps)
			}
			t.Logf("parameters=%d physical=%d bundle=%d reserved=%d wraps=%d unwraps=%d", len(want), b.PhysicalBytes(), len(wire), e.Registration.ReservedBytes(), keys.wraps, keys.unwraps)
		})
	}
}

func TestHistoryParametersRefuseSubstitutionAndCiphertextChanges(t *testing.T) {
	p, e, mac := historyParametersFixture(t)
	keys := &historyTestKeys{}
	b, err := SealHistoryParameters(t.Context(), e, p, keys, mac)
	if err != nil {
		t.Fatal(err)
	}
	b, c := historyFinalBundle(t, e, b)
	defer b.Clear()
	for _, change := range []func(*value.HistoryExpectation){func(x *value.HistoryExpectation) { x.CaptureID = "10000000-0000-4000-8000-000000000099" }, func(x *value.HistoryExpectation) {
		x.Registration.ExpiresAt = x.Registration.ExpiresAt.Add(time.Minute)
	}, func(x *value.HistoryExpectation) { x.SettingsKey[0] ^= 1 }, func(x *value.HistoryExpectation) { x.SelectorKey[0] ^= 1 }} {
		x := e
		change(&x)
		if _, err := OpenHistoryParameters(t.Context(), x, c, b, keys, mac); err == nil {
			t.Fatal("accepted substituted expectation")
		}
	}
	for i := range b {
		x := b
		x[i] = bytes.Clone(b[i])
		x[i][len(x[i])/2] ^= 1
		if _, err := OpenHistoryParameters(t.Context(), e, c, x, keys, mac); err == nil {
			t.Fatal("accepted changed object", i)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := OpenHistoryParameters(ctx, e, c, b, keys, mac); err == nil {
		t.Fatal("cancelled history read")
	}
}

func TestHistoryBundleBoundBeforeDecode(t *testing.T) {
	var b HistoryBundle
	for i, n := range historyObjectLimits {
		b[i] = bytes.Repeat([]byte{byte(i + 1)}, int(n))
	}
	wire, err := EncodeHistoryBundle(b)
	if err != nil || len(wire) > HistoryBundleMaxBytes {
		t.Fatal("derived wire bound does not cover all role bounds", len(wire), err)
	}
	if _, err = DecodeHistoryBundle(wire); err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeHistoryBundle(bytes.Repeat([]byte{'x'}, HistoryBundleMaxBytes+1)); err == nil {
		t.Fatal("oversize wire accepted")
	}
	if _, err = DecodeHistoryBundle([]byte(`["eA==","eA==","eA==","eA==","eA=="]`)); err == nil {
		t.Fatal("extra object ignored")
	}
	b[1] = append(b[1], 1)
	if _, err = EncodeHistoryBundle(b); err == nil {
		t.Fatal("oversized role accepted")
	}
}
