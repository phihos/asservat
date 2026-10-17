package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func testID(n int) string { return fmt.Sprintf("10000000-0000-4000-8000-%012x", n) }
func fixture(t *testing.T) (*Validator, artifact.ContextExpectation, artifact.Layout, artifact.Copies, []byte) {
	t.Helper()
	v, err := New()
	if err != nil {
		t.Fatal(err)
	}
	d := artifact.Digest(sha256.Sum256([]byte("synthetic")))
	a := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	e := artifact.ContextExpectation{
		Registration: artifact.Registration{Location: artifact.Location{ClusterID: testID(1), ArtifactID: testID(2), AttemptID: testID(3)}, StoreID: testID(4), AllocationID: testID(5), PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: a, WriteUntil: a.Add(time.Minute), ExpiresAt: a.Add(2 * time.Minute), DeleteBy: a.Add(3 * time.Minute)},
		CaseID:       testID(6), OccurrenceID: testID(7), NodeUID: "node-uid", NodeBootID: testID(8), PodUID: "pod-uid", Namespace: "synthetic", NamespaceUID: "namespace-uid", WorkloadUID: "workload-uid", CollectorVersion: "synthetic-test", CollectorImageDigest: d, RecipeDigest: d, PlanDigest: d, CaptureUID: testID(9), ActionID: "context", DataClass: "metadata", PurposeRef: "synthetic-test",
		Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.example.invalid", SubjectID: "synthetic-team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding-uid", AssignmentID: testID(10), BasisDigest: d}}, RequestedAgeSeconds: 120, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 60, RetentionRules: []artifact.RetentionRule{{UID: "retention-uid", Generation: 1, Digest: d}}, TriggeredAt: a,
	}
	l := artifact.Layout{Format: artifact.StorageFormat, Binding: e.Binding(), NativeBytes: 353, DataBytes: 500, IndexBytes: 1000, NativeSHA256: d, DataSHA256: d, IndexSHA256: d, DataKey: artifact.SealedKey{Reference: "transit/evidence", Ciphertext: "synthetic-data-key"}, IndexKey: artifact.SealedKey{Reference: "transit/evidence", Ciphertext: "synthetic-index-key"}, Pages: []artifact.Page{{Number: 0, FirstFrame: 0, FrameCount: 1, NativeOffset: 0, NativeBytes: 353, DataOffset: 0, DataBytes: 500, IndexOffset: 0, IndexBytes: 1000, IndexSHA256: d}}}
	var c artifact.Copies
	for i := range c {
		c[i] = artifact.CopyReceipt{VersionID: fmt.Sprint(i), ETag: fmt.Sprintf("\"synthetic-%d\"", i), Bytes: 1000, SHA256: d}
	}
	c[0].Bytes = 500
	b, err := v.MarshalContext(e, l, c, a, a.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return v, e, l, c, b
}

func mutate(t *testing.T, b []byte, fn func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		t.Fatal("fixture JSON")
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func obj(m map[string]any, k string) map[string]any { return m[k].(map[string]any) }

func TestContextManifestRejectsChangedClaims(t *testing.T) {
	v, e, _, c, b := fixture(t)
	if _, err := v.ParseContext(b, e, c); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]any){
		"foreign cluster":       func(m map[string]any) { obj(m, "target")["clusterID"] = testID(20) },
		"foreign artifact":      func(m map[string]any) { m["artifactID"] = testID(20) },
		"foreign case":          func(m map[string]any) { m["caseID"] = testID(20) },
		"foreign occurrence":    func(m map[string]any) { m["occurrenceID"] = testID(20) },
		"replacement pod":       func(m map[string]any) { obj(m, "target")["podUID"] = "new-pod" },
		"replacement namespace": func(m map[string]any) { obj(m, "accessProvenance")["namespaceUID"] = "new-namespace" },
		"replacement boot":      func(m map[string]any) { obj(m, "target")["nodeBootID"] = testID(20) },
		"target container":      func(m map[string]any) { obj(m, "target")["containerID"] = "forged-container" },
		"scope promotion":       func(m map[string]any) { m["dataClass"] = "extract" },
		"privacy downgrade":     func(m map[string]any) { obj(m, "privacy")["classification"] = "unknown" },
		"purpose":               func(m map[string]any) { obj(m, "privacy")["purposeRef"] = "changed-purpose" },
		"changed owner": func(m map[string]any) {
			a := obj(m, "accessProvenance")["assignments"].([]any)[0].(map[string]any)
			obj(a, "subject")["id"] = "foreign-team"
		},
		"grant invented":     func(m map[string]any) { m["authorized"] = true },
		"expiry extension":   func(m map[string]any) { m["expiresAt"] = "2026-10-09T12:04:00Z" },
		"deletion extension": func(m map[string]any) { obj(m, "retention")["deleteBy"] = "2026-10-09T12:04:00Z" },
		"anchor reset":       func(m map[string]any) { obj(m, "retention")["anchorAt"] = "2026-10-09T12:00:01Z" },
		"retention policy": func(m map[string]any) {
			p := obj(m, "retention")["policyRefs"].([]any)[0].(map[string]any)
			p["generation"] = 2
		},
		"plan":                   func(m map[string]any) { obj(m, "collectionProvenance")["planDigest"] = strings.Repeat("f", 64) },
		"capture":                func(m map[string]any) { obj(m, "collectionProvenance")["captureUID"] = testID(20) },
		"action":                 func(m map[string]any) { obj(m, "collectionProvenance")["actionID"] = "different-action" },
		"manual policy invented": func(m map[string]any) { obj(m, "collector")["policyDigest"] = strings.Repeat("f", 64) },
		"collector identity":     func(m map[string]any) { obj(m, "collector")["imageDigest"] = strings.Repeat("f", 64) },
		"projection":             func(m map[string]any) { obj(m, "provenance")["projectionDigest"] = strings.Repeat("f", 64) },
		"parent laundering": func(m map[string]any) {
			obj(m, "provenance")["parentArtifacts"] = []any{map[string]any{"artifactID": testID(20), "digest": strings.Repeat("f", 64)}}
		},
		"raw filename":       func(m map[string]any) { m["filename"] = "SYNTHETIC-SECRET" },
		"layout hash":        func(m map[string]any) { obj(m, "hashes")["plaintextSHA256"] = strings.Repeat("f", 64) },
		"layout size":        func(m map[string]any) { obj(m, "sizes")["plaintextBytes"] = 354 },
		"data version":       func(m map[string]any) { obj(obj(m, "storageObjects"), "data")["versionID"] = "replacement" },
		"index identity":     func(m map[string]any) { obj(obj(m, "storageObjects"), "index")["etag"] = "replacement" },
		"invalid time":       func(m map[string]any) { m["completedAt"] = "not-a-date" },
		"reversed time":      func(m map[string]any) { m["completedAt"] = "2026-10-09T11:59:59Z" },
		"late completion":    func(m map[string]any) { m["completedAt"] = "2026-10-09T12:02:00Z" },
		"truncated source":   func(m map[string]any) { obj(m, "completeness")["source"] = "truncated" },
		"unqualified format": func(m map[string]any) { m["format"] = "arbitrary-json/v1" },
		"null scalar":        func(m map[string]any) { obj(m, "sizes")["plaintextBytes"] = nil },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.ParseContext(mutate(t, b, fn), e, c)
			if err == nil {
				t.Fatal("untrusted claim accepted")
			}
			if strings.Contains(err.Error(), "SYNTHETIC-SECRET") {
				t.Fatal("input in error")
			}
		})
	}
}

func TestCommitStrictBinding(t *testing.T) {
	v, e, _, c, _ := fixture(t)
	key := artifact.SealedKey{Reference: "transit/evidence", Ciphertext: "synthetic-wrapped-key"}
	b, err := v.MarshalCommit(e.Registration.Location, c[2], key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v.ParseCommit(b, e.Registration.Location, c[2]); err != nil || got != key {
		t.Fatal(err)
	}
	for _, field := range []string{"clusterID", "artifactID", "attemptID"} {
		bad := mutate(t, b, func(m map[string]any) { m[field] = testID(55) })
		if _, err := v.ParseCommit(bad, e.Registration.Location, c[2]); err == nil {
			t.Fatal(field)
		}
	}
	for _, field := range []string{"etag", "versionID"} {
		bad := mutate(t, b, func(m map[string]any) { obj(obj(m, "manifest"), "identity")[field] = "wrong" })
		if _, err := v.ParseCommit(bad, e.Registration.Location, c[2]); err == nil {
			t.Fatal(field)
		}
	}
	bad := append(append([]byte{}, b...), b...)
	if _, err := v.ParseCommit(bad, e.Registration.Location, c[2]); err == nil {
		t.Fatal("trailing document")
	}
	bad = append([]byte(`{"format":"artifact-commit/v1",`), b[1:]...)
	if _, err := v.ParseCommit(bad, e.Registration.Location, c[2]); err == nil {
		t.Fatal("duplicate key")
	}
	c[2].VersionID = ""
	b, err = v.MarshalCommit(e.Registration.Location, c[2], key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.ParseCommit(b, e.Registration.Location, c[2]); err != nil {
		t.Fatal("explicit unversioned identity rejected", err)
	}
}

func TestNativeProjectionRejectsHiddenAndInconsistentData(t *testing.T) {
	v, e, _, c, b := fixture(t)
	m, err := v.ParseContext(b, e, c)
	if err != nil {
		t.Fatal(err)
	}
	pod := podDTO{Format: artifact.ContextFormat, NamespaceUID: e.NamespaceUID, PodUID: e.PodUID, ResourceVersion: "opaque-rv", ObservedAt: m.StartedAt.Add(time.Millisecond), Phase: "Running", Ready: "True", Initialized: "True", Scheduled: "True", RuntimeInstances: 1, Running: 1}
	native, _ := json.Marshal(pod)
	if err = v.ValidateNative(native, e, m); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"argv", "environment", "labels", "annotations", "containerNames", "message"} {
		bad := mutate(t, native, func(o map[string]any) { o[field] = "SYNTHETIC-SECRET" })
		if err = v.ValidateNative(bad, e, m); err == nil {
			t.Fatal(field)
		}
	}
	for name, fn := range map[string]func(map[string]any){"wrong pod": func(o map[string]any) { o["podUID"] = "foreign" }, "wrong namespace": func(o map[string]any) { o["namespaceUID"] = "foreign" }, "impossible states": func(o map[string]any) { o["waiting"] = 1 }, "old observation": func(o map[string]any) { o["observedAt"] = "2026-10-08T00:00:00Z" }, "null count": func(o map[string]any) { o["running"] = nil }} {
		t.Run(name, func(t *testing.T) {
			if err := v.ValidateNative(mutate(t, native, fn), e, m); err == nil {
				t.Fatal("invalid projection")
			}
		})
	}
}

func TestStrictJSONBoundsAndOfflineLoader(t *testing.T) {
	for _, b := range [][]byte{[]byte(`{"a":1,"a":2}`), []byte(`{"a":null} {}`), []byte(`{"a":1e999999}`), []byte(`{"a":9007199254740991000000000}`), []byte(`{"a":"\ud800"}`), append([]byte(`{"a":"`), 0xff, '"', '}'), []byte(strings.Repeat("[", 34) + strings.Repeat("]", 34))} {
		if _, err := strict(b, artifact.MaxRootBytes); err == nil {
			t.Fatalf("unbounded or ambiguous JSON accepted %q", b)
		}
	}
	if _, err := strict(bytes.Repeat([]byte(" "), int(artifact.MaxRootBytes)+1), artifact.MaxRootBytes); !errors.Is(err, artifact.ErrLimit) {
		t.Fatal(err)
	}
	if _, err := (denyLoader{}).Load("https://example.invalid/schema"); err == nil {
		t.Fatal("network loader")
	}
}

func FuzzManifest(f *testing.F) {
	v, err := New()
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"artifactID":null}`))
	f.Add([]byte(`{"a":1e99999}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > int(artifact.MaxRootBytes)+1 {
			return
		}
		err := validate(v.manifest, b, artifact.MaxRootBytes)
		if err != nil && err != artifact.ErrInvalid && err != artifact.ErrLimit {
			t.Fatal("unbounded diagnostic")
		}
	})
}
