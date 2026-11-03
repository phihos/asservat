package objectstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/pprof/profile"
)

func TestProjectionComparisonReaderAuthenticatesBeforeTypedMismatch(t *testing.T) {
	for _, mode := range []string{"complete", "mismatch", "early-mismatch", "bad-hash-mismatch", "oversize", "early-oversize", "bad-hash-oversize", "input-limit", "uninstalled"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			f := prepareProfileEncryptedFixture(t, dir, bytes.NewReader(comparisonEncryptedNative(t, 7)), mode == "bad-hash-mismatch" || mode == "bad-hash-oversize")
			verifier, _, _, unblock := profileEncryptedVerifier(t, dir, f, false)
			defer unblock()
			scope := f.Scope
			scope.DisplayVersion = query.ProfileComparisonDisplayVersion
			s := f.Scope
			scope.Comparison = query.ProfileComparisonWindow{Normalization: query.ProfileComparisonRaw, Baseline: query.ProfileComparisonBaseline{CaseID: s.CaseID, ArtifactID: s.ArtifactID, CaptureID: s.CaptureID, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: s.PodUID, Version: s.Version}}
			reader, _ := NewContextProjectionReader(verifier.store)
			if mode != "uninstalled" {
				reader.ServeProfileComparisons(diagnostics.ComparePprof)
			}
			if mode != "complete" && mode != "uninstalled" {
				reader.ServeProfileComparisons(func(ctx context.Context, b io.Reader, _ query.ProfileComparisonAcquisition, i io.Reader, _ query.ProfileComparisonAcquisition, _ query.ProfileComparisonSelection) (query.ProfileComparison, error) {
					if mode != "early-mismatch" && mode != "early-oversize" {
						_, _ = io.Copy(io.Discard, b)
						_, _ = io.Copy(io.Discard, i)
					}
					if mode == "oversize" || mode == "early-oversize" || mode == "bad-hash-oversize" {
						return query.ProfileComparison{}, query.ErrRecordTooLarge
					}
					if mode == "input-limit" {
						return query.ProfileComparison{}, artifact.ErrLimit
					}
					return query.ProfileComparison{}, query.ErrProfileIncompatible
				})
			}
			keys := [2]*projectionTestOpener{{}, {}}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			until, _ := ctx.Deadline()
			result, err := reader.ReadProjectionComparisonNative(ctx, [2]evidence.NativeContextSource{f.Source, f.Source}, scope, [2]evidence.KeyOpener{keys[0], keys[1]}, until)
			switch mode {
			case "complete":
				if err != nil || !result.Valid(scope) || result.Comparison == nil || result.Comparison.Rows[0].Delta != 0 {
					t.Fatal("same source comparison", result, err)
				}
			case "mismatch":
				if err != nil || !result.Valid(scope) || !result.IncompatibleProfiles {
					t.Fatal("authenticated mismatch not retained", result, err)
				}
			case "oversize":
				if err != nil || !result.Valid(scope) || !result.TooLarge || result.IncompatibleProfiles || result.Comparison != nil {
					t.Fatal("authenticated size refusal not retained", result, err)
				}
			default:
				if err == nil || result.Valid(scope) || result.IncompatibleProfiles || result.TooLarge || result.Comparison != nil {
					t.Fatal("incomplete input disclosed semantic mismatch", result, err)
				}
			}
			want := 3
			if mode == "uninstalled" {
				want = 0
			}
			if keys[0].calls != want || keys[1].calls != want {
				t.Fatal("independent three-role opens", keys[0].calls, keys[1].calls)
			}
		})
	}
}

func TestComparisonRawOutputLimitBecomesAuthenticatedRefusal(t *testing.T) {
	p, err := profile.ParseData(comparisonEncryptedNative(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	p.Function, p.Location, p.Sample = nil, nil, nil
	for n := range 100 {
		function := &profile.Function{ID: uint64(n + 1), Name: fmt.Sprintf("%03d.%s", n, strings.Repeat("<", 508))}
		location := &profile.Location{ID: uint64(n + 1), Line: []profile.Line{{Function: function}}}
		p.Function = append(p.Function, function)
		p.Location = append(p.Location, location)
		p.Sample = append(p.Sample, &profile.Sample{Location: []*profile.Location{location}, Value: []int64{1}})
	}
	var native bytes.Buffer
	if err := p.Write(&native); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := prepareProfileEncryptedFixture(t, dir, bytes.NewReader(native.Bytes()), false)
	f.Scope.Profile.TopN = 100
	scope := f.Scope
	scope.DisplayVersion = query.ProfileComparisonDisplayVersion
	s := f.Scope
	scope.Comparison = query.ProfileComparisonWindow{Normalization: query.ProfileComparisonRaw, Baseline: query.ProfileComparisonBaseline{CaseID: s.CaseID, ArtifactID: s.ArtifactID, CaptureID: s.CaptureID, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: s.PodUID, Version: s.Version}}
	verifier, _, _, unblock := profileEncryptedVerifier(t, dir, f, false)
	defer unblock()
	reader, _ := NewContextProjectionReader(verifier.store)
	reader.ServeProfileComparisons(diagnostics.ComparePprof)
	keys := [2]*projectionTestOpener{{}, {}}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	until, _ := ctx.Deadline()
	result, err := reader.ReadProjectionComparisonNative(ctx, [2]evidence.NativeContextSource{f.Source, f.Source}, scope, [2]evidence.KeyOpener{keys[0], keys[1]}, until)
	if err != nil || !result.Valid(scope) || !result.TooLarge || result.IncompatibleProfiles || result.Comparison != nil || keys[0].calls != 3 || keys[1].calls != 3 {
		t.Fatal("real parser output lost authenticated refusal", result, err, keys[0].calls, keys[1].calls)
	}
}

// Real remote opener requests carry two different child UUIDs even when the
// artifact/AAD is identical. Provider authority/unwraps are synthetic here;
// this does not qualify production SQL, KMS or worker identity.
func TestNativeComparisonReaderUsesTwoIndependentRemoteKeyChildren(t *testing.T) {
	dir := t.TempDir()
	keyScope := value.KeyScope{InstallationID: testProjectionScope().RootID, Purpose: "artifact", KeyID: "synthetic"}
	f := prepareProfileEncryptedFixture(t, dir, bytes.NewReader(comparisonEncryptedNative(t, 7)), false, comparisonRemoteFixtureSealer{scope: keyScope})
	verifier, _, _, unblock := profileEncryptedVerifier(t, dir, f, false)
	defer unblock()
	scope := f.Scope
	scope.DisplayVersion = query.ProfileComparisonDisplayVersion
	s := f.Scope
	scope.Comparison = query.ProfileComparisonWindow{Normalization: query.ProfileComparisonRaw, Baseline: query.ProfileComparisonBaseline{CaseID: s.CaseID, ArtifactID: s.ArtifactID, CaptureID: s.CaptureID, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: s.PodUID, Version: s.Version}}
	ids, _ := query.ProfileComparisonKeyChildIDs(scope.RootID)
	var mu sync.Mutex
	spent := map[string]map[string]bool{ids[0]: {}, ids[1]: {}}
	keyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := contracts.DecodeKeyRequest(r.Body)
		if err != nil || request.Operation != "unwrap" || request.Sealed == nil {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		roles, ok := spent[request.AuthorityID]
		reused := ok && roles[string(request.Binding)]
		if ok && !reused {
			roles[string(request.Binding)] = true
		}
		mu.Unlock()
		if !ok || reused {
			w.WriteHeader(403)
			return
		}
		info, err := authapp.DescribeKeyRequest(value.KeyRequest{Scope: value.KeyScope{InstallationID: request.Scope.InstallationID, Purpose: request.Scope.Purpose, KeyID: request.Scope.KeyID}, AuthorityID: request.AuthorityID, Operation: request.Operation, Binding: request.Binding, Sealed: artifact.SealedKey{Reference: request.Sealed.Reference, Ciphertext: request.Sealed.Ciphertext}})
		if err != nil {
			w.WriteHeader(400)
			return
		}
		key, err := base64.StdEncoding.DecodeString(request.Sealed.Ciphertext)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		defer clear(key)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contracts.KeyServiceResponse{Format: contracts.KeyServiceFormat, Operation: "unwrap", Output: key, RequestSHA256: hex.EncodeToString(info.RequestDigest[:]), ValidUntil: time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)})
	}))
	defer keyServer.Close()
	client := keyServer.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{keyServer.TLS.Certificates[0]}
	reader, err := NewNativeContextReader(verifier.store, keyScope, keyServer.URL, client)
	if err != nil {
		t.Fatal(err)
	}
	reader.ServeProfileComparisons(diagnostics.ComparePprof)
	now := time.Now().UTC()
	until := now.Add(10 * time.Second)
	rev := identity.Revision{UID: scope.RootID, Generation: 1, Digest: artifact.Digest{1}}
	path := artifact.DownloadPath{ID: scope.RootID, TargetClusterID: scope.ClusterID, StoreID: f.Source.Expectation.Registration.StoreID, StorageRegion: "fixture", AcquisitionClusterID: scope.RootID, AcquisitionRegion: "fixture", ConnectorClusterID: scope.RootID, ConnectorRegion: "fixture", HubClusterID: scope.RootID, HubRegion: "fixture", WorkerConfiguration: rev, HubConfiguration: rev}
	proof := artifact.DownloadProcessingProof{RootID: scope.RootID, Epoch: scope.RootID, CaptureID: scope.CaptureID, Location: f.Source.Expectation.Registration.Location, Sequence: 1, StateDigest: artifact.Digest{1}, ObservedAt: now, ValidUntil: until}
	o := value.NativeOperation{Path: path, Processing: proof, Reference: value.NativeReference{InstallationID: scope.RootID, QueryID: scope.RootID, WorkerID: scope.RootID, OperationID: scope.RootID, Fence: 1}, Kind: value.NativeProjection, HubPodUID: scope.RootID, HubProcessEpoch: scope.RootID, WorkerPodUID: scope.RootID, WorkerPublicKey: artifact.Digest{1}, SourceVersion: scope.Version, ParentID: scope.RootID, Generation: 1, StartedAt: now, Until: until, Baseline: value.NativeProjectionSource{Path: path, Processing: proof, SourceVersion: scope.Version}}
	ctx, cancel := context.WithDeadline(t.Context(), until)
	defer cancel()
	result, err := reader.ReadApprovedProfileComparison(ctx, [2]evidence.NativeContextSource{f.Source, f.Source}, o, scope, until)
	if err != nil || !result.Valid(scope) || result.Comparison == nil {
		t.Fatal("paired remote-key read", err, result)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(spent[ids[0]]) != 3 || len(spent[ids[1]]) != 3 {
		t.Fatal("not six independent roles", spent)
	}
}

type comparisonRemoteFixtureSealer struct{ scope value.KeyScope }

func (s comparisonRemoteFixtureSealer) Seal(_ context.Context, key, _ []byte) (artifact.SealedKey, error) {
	return artifact.SealedKey{Reference: "asservat-local-keyset/v1/" + s.scope.InstallationID + "/" + s.scope.Purpose + "/" + s.scope.KeyID + "/1", Ciphertext: base64.StdEncoding.EncodeToString(key)}, nil
}
