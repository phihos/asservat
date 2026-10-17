package kubernetes

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// Actual TLS qualifies only the original-object read and its finite deadline.
// Journal, native enforcement and accepted SQL facts remain synthetic here.
func TestOwnerIdentityProjectionReadsExactOriginalTemplateBeforeClaims(t *testing.T) {
	for _, mode := range []string{"original", "different-input-template", "different-input-image", "changed-native-template", "replacement", "guard-receipt", "guard-generation", "binding-version", "expired-snapshot", "blocked-original-deadline", "blocked-snapshot-deadline"} {
		t.Run(mode, func(t *testing.T) {
			root, in, state := ownerProjectionOriginalInputFixture(t)
			state.OwnerIdentity, state.OwnerLaunch = nil, nil
			object, e := root.resources.object(state, 10)
			if e != nil {
				t.Fatal(e)
			}
			d := object.object.(*apps.Deployment)
			d.UID = types.UID(state.Objects[10].Receipt.UID)
			d.ResourceVersion = state.Objects[10].Receipt.ResourceVersion
			d.Generation = 1
			d.Annotations = map[string]string{initialRuntimeResourceMarker: state.Objects[10].OperationID}
			// Scalar defaults are the fixed native-qualified API response shape. The
			// two tolerations must come from the original installed builder itself.
			d.Spec.Template.Spec.DNSPolicy = core.DNSClusterFirst
			d.Spec.Template.Spec.SchedulerName = core.DefaultSchedulerName
			d.Spec.Template.Spec.Containers[0].TerminationMessagePath = core.TerminationMessagePathDefault
			d.Spec.Template.Spec.Containers[0].TerminationMessagePolicy = core.TerminationMessageReadFile
			digest, e := ConnectorAPITemplateDigest(d.Spec.Template)
			if e != nil {
				t.Fatal("installed builder lacks native pin shape", e)
			}
			in.Observation.TemplateDigest = hex.EncodeToString(digest[:])
			in.Observation.ImageDigest = strings.Split(d.Spec.Template.Spec.Containers[0].Image, "@sha256:")[1]
			switch mode {
			case "different-input-template":
				in.Observation.TemplateDigest = strings.Repeat("f", 64)
			case "different-input-image":
				in.Observation.ImageDigest = strings.Repeat("f", 64)
			case "changed-native-template":
				d.Spec.Template.Annotations = map[string]string{"unreviewed": "changed"}
			case "replacement":
				d.UID = types.UID(ownerID(7250))
			case "guard-receipt":
				copy := *state.Objects[17].Receipt
				copy.UID = ownerID(7251)
				state.Objects[17].Receipt = &copy
			case "guard-generation":
				copy := *state.Objects[17].Receipt
				copy.Generation++
				state.Objects[17].Receipt = &copy
			case "binding-version":
				copy := *state.Objects[18].Receipt
				copy.ResourceVersion = "changed"
				state.Objects[18].Receipt = &copy
			}
			var calls atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("input validation wrote an object")
					http.Error(w, "method", 405)
					return
				}
				calls.Add(1)
				if strings.HasPrefix(mode, "blocked-") {
					close(entered)
					<-release
				}
				permissionReply(w, d)
			}))
			defer server.Close()
			defer close(release)
			client, e := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, in.ClusterID, cfg.NamespaceRef{Name: in.Namespace.Name, UID: in.Namespace.UID}, time.Now)
			if e != nil {
				t.Fatal(e)
			}
			root.bridge.source.client = client
			s := &OwnerIdentityProjection{root: root, input: in}
			snapshot := contracts.InitialRuntimeResourceSnapshot{State: state, ValidUntil: time.Now().Add(3 * time.Second)}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if mode == "expired-snapshot" {
				snapshot.ValidUntil = time.Now().Add(-time.Second)
			}
			if strings.HasPrefix(mode, "blocked-") {
				call := ctx
				if mode == "blocked-original-deadline" {
					var end context.CancelFunc
					call, end = context.WithTimeout(ctx, 50*time.Millisecond)
					defer end()
				} else {
					snapshot.ValidUntil = time.Now().Add(50 * time.Millisecond)
				}
				result := make(chan error, 1)
				go func() { result <- s.originalInput(call, snapshot) }()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("original read did not enter")
				}
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("blocked read renewed original caller bound")
					}
				case <-ctx.Done():
					t.Fatal("original read did not join cancellation")
				}
			} else {
				e = s.originalInput(ctx, snapshot)
				if (mode == "original") != (e == nil) {
					t.Fatalf("original template outcome: %v", e)
				}
			}
			want := int32(1)
			if mode == "guard-receipt" || mode == "guard-generation" || mode == "binding-version" || mode == "expired-snapshot" {
				want = 0
			}
			if calls.Load() != want {
				t.Fatal("input validation repeated read or bypassed original guard receipt", calls.Load())
			}
		})
	}
}
