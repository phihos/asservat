package kubernetes

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestInitialBootstrapCopyCASUnknownCannotBecomeFreshCreate(t *testing.T) {
	for _, requireAcknowledgement := range []bool{false, true} {
		t.Run(strconv.FormatBool(requireAcknowledgement), func(t *testing.T) {
			f := newBootstrapPassiveFixtureVersion(t, true, contracts.InitialBootstrapCopyClosureFormat)
			if _, err := f.producer.ReadPassiveHistory(context.Background()); err != nil {
				t.Fatal("current original public proof", err)
			}
			prior := f.extra
			writes := 0
			f.extra = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/secrets/"+f.metadata.Name) {
					if r.Header.Get("Accept") != bootstrapPartialMetadataAccept {
						t.Error("copy CAS requested broad seed")
					}
					var ops []struct {
						Op, Path string
						Value    json.RawMessage
					}
					if json.NewDecoder(r.Body).Decode(&ops) != nil || len(ops) != 3 {
						t.Error("unexpected metadata CAS")
					}
					var uid, rv, value string
					_ = json.Unmarshal(ops[0].Value, &uid)
					_ = json.Unmarshal(ops[1].Value, &rv)
					_ = json.Unmarshal(ops[2].Value, &value)
					if uid != string(f.metadata.UID) || rv != f.metadata.ResourceVersion || ops[0].Op != "test" || ops[1].Op != "test" {
						t.Error("original UID/RV missing")
					}
					writes++
					key := strings.ReplaceAll(strings.TrimPrefix(ops[2].Path, "/metadata/annotations/"), "~1", "/")
					f.metadata.Annotations[key] = value
					f.metadata.ResourceVersion = "18"
					http.Error(w, "committed reply unavailable", 503)
					return true
				}
				return prior(w, r)
			}
			original := f.metadata.DeepCopy()
			at := time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
			got, err := f.producer.copyAnnotationMode(context.Background(), original, bootstrapCopyPolicyStartedAnnotation, at, false, requireAcknowledgement)
			if requireAcknowledgement {
				if err == nil || got != nil {
					t.Fatal("unknown claim reply authorized first CREATE")
				}
			} else if err != nil || got == nil || got.UID != original.UID {
				t.Fatal("same original committed metadata did not recover", err)
			}
			if writes != 1 || f.metadata.Annotations[bootstrapCopyPolicyStartedAnnotation] != at || f.seedFullReads != 0 {
				t.Fatal("lost reply rewrote claim or loaded private seed")
			}
		})
	}
}
func TestInitialBootstrapCopySanitizationIsOneExactImmutableCAS(t *testing.T) {
	f := newBootstrapPassiveFixtureVersion(t, true, contracts.InitialBootstrapCopyClosureFormat)
	if _, err := f.producer.ReadPassiveHistory(context.Background()); err != nil {
		t.Fatal(err)
	}
	prior := f.extra
	sanitized := false
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/secrets/"+f.metadata.Name) {
			var ops []struct {
				Op, Path string
				Value    json.RawMessage
			}
			if json.NewDecoder(r.Body).Decode(&ops) != nil || len(ops) != 5 {
				t.Error("split/noncanonical sanitization")
				http.Error(w, "invalid", 400)
				return true
			}
			var data map[string]string
			var immutable bool
			var stamp string
			_ = json.Unmarshal(ops[3].Value, &data)
			_ = json.Unmarshal(ops[4].Value, &immutable)
			_ = json.Unmarshal(ops[2].Value, &stamp)
			if ops[3].Op != "replace" || ops[3].Path != "/data" || len(data) != 1 || data["retired"] != "dHJ1ZQ==" || ops[4].Path != "/immutable" || !immutable {
				t.Error("private material not atomically removed/frozen")
			}
			sanitized = true
			f.metadata.Annotations[bootstrapCopyCompleteAnnotation] = stamp
			f.metadata.ResourceVersion = "18"
			permissionReply(w, &f.metadata)
			return true
		}
		return prior(w, r)
	}
	got, err := f.producer.copyAnnotation(context.Background(), f.metadata.DeepCopy(), bootstrapCopyCompleteAnnotation, time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), true)
	if err != nil || got == nil || !sanitized || f.seedFullReads != 0 {
		t.Fatal("sanitization did not retain metadata-only exact identity", err)
	}
}
func TestInitialBootstrapCopyCASRetainsOriginalCancellation(t *testing.T) {
	f := newBootstrapPassiveFixtureVersion(t, true, contracts.InitialBootstrapCopyClosureFormat)
	if _, err := f.producer.ReadPassiveHistory(context.Background()); err != nil {
		t.Fatal(err)
	}
	prior := f.extra
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPatch {
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 8193))
			_ = r.Body.Close()
			entered <- struct{}{}
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return true
		}
		return prior(w, r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := f.producer.copyAnnotation(ctx, f.metadata.DeepCopy(), bootstrapCopyPolicyStartedAnnotation, time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), false)
		result <- err
	}()
	select {
	case <-entered:
		cancel()
	case <-ctx.Done():
		t.Fatal("did not reach blocked exact CAS")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled CAS returned authority")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled copy CAS did not join")
	}
	if f.seedFullReads != 0 || f.metadata.Annotations[bootstrapCopyPolicyStartedAnnotation] != "" {
		t.Fatal("cancellation read private state or fabricated receipt")
	}
}

// The first persisted create claim and the original HTTP response are separate
// facts. A lost claim reply cannot issue a first CREATE in that process or on
// restart, even when an exact lookup currently returns absence.
func TestInitialBootstrapCopyGuardLostClaimNeverPostsOrReclaims(t *testing.T) {
	f := newBootstrapPassiveFixtureVersion(t, true, contracts.InitialBootstrapCopyClosureFormat)
	if _, err := f.producer.ReadPassiveHistory(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, metadata, passive := bootstrapCopyStateFixture(t)
	state, err := bootstrapReadCopyState(f.desired, metadata, passive)
	if err != nil {
		t.Fatal(err)
	}
	state.PolicyStartedAt, state.Policy, state.BindingStartedAt, state.Binding = nil, nil, nil, nil
	want, _, err := InitialBootstrapCopyAdmission(f.desired, state.Claim)
	if err != nil {
		t.Fatal(err)
	}
	prior := f.extra
	patches, posts, lookups := 0, 0, 0
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/secrets/"+f.metadata.Name) {
			var ops []struct {
				Op, Path string
				Value    json.RawMessage
			}
			if json.NewDecoder(r.Body).Decode(&ops) != nil || len(ops) != 3 {
				t.Error("invalid original create claim CAS")
				http.Error(w, "invalid", 400)
				return true
			}
			var value string
			_ = json.Unmarshal(ops[2].Value, &value)
			f.metadata.Annotations[bootstrapCopyPolicyStartedAnnotation] = value
			f.metadata.ResourceVersion = "18"
			patches++
			http.Error(w, "acknowledgement lost", 503)
			return true
		}
		if strings.Contains(r.URL.Path, "/validatingadmissionpolicies") && (strings.HasSuffix(r.URL.Path, "/"+want.Name) || r.Method == http.MethodPost) {
			if r.Method == http.MethodPost {
				posts++
			} else {
				lookups++
			}
			bootstrapPassiveNotFound(w)
			return true
		}
		return prior(w, r)
	}
	if err := f.producer.advanceCopyGuard(context.Background(), f.metadata.DeepCopy(), state, want, true); err == nil {
		t.Fatal("lost first claim response accepted")
	}
	if patches != 1 || posts != 0 || lookups != 0 {
		t.Fatal("unknown original claim crossed the CREATE boundary", patches, posts, lookups)
	}
	at, err := time.Parse(time.RFC3339Nano, f.metadata.Annotations[bootstrapCopyPolicyStartedAnnotation])
	if err != nil {
		t.Fatal(err)
	}
	state.PolicyStartedAt = &at
	for range 2 {
		if err := f.producer.advanceCopyGuard(context.Background(), f.metadata.DeepCopy(), state, want, true); err == nil {
			t.Fatal("absent original object interpreted as successful creation")
		}
	}
	if patches != 1 || posts != 0 || lookups != 2 || f.seedFullReads != 0 {
		t.Fatal("replay refilled a claim or loaded broad seed", patches, posts, lookups)
	}
}
