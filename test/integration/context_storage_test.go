package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	targets "asservat.local/asservat/internal/domain/targets"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type fixture struct {
	S3, KMS, Postgres string
	// PostgresContainer names the owned PostgreSQL container (installed
	// journey: lossless restart, ADR-226).
	PostgresContainer string
	WorkerImage       string
	// UpgradeImage is the focused upgrade run's second release image, loaded
	// into the hub cluster only (ADR-227).
	UpgradeImage    string
	NativeProviders struct {
		S3, KMS, Postgres string
		Root              []byte
	}
	Clusters []struct {
		Config, Token, TargetToken       string
		NodeUID, NodeBootID, WorkloadUID string
		Pod                              artifact.PinnedPod
	}
	// Identity is the owned Keycloak of the installed journey; only the
	// installer-continuation harness starts one.
	Identity *struct {
		Base, RootCA, AdminUser, AdminPassword, UserPassword string
	}
}

func request(t *testing.T, endpoint, token, path string, payload any, want int) map[string]any {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(http.MethodPost, endpoint+"/v1/"+path, bytes.NewReader(b))
	if err != nil {
		t.Fatal("request construction")
	}
	r.Header.Set("X-Vault-Token", token)
	r.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	v, err := c.Do(r)
	if err != nil {
		t.Fatal("fixture request failed")
	}
	defer v.Body.Close()
	if v.StatusCode != want {
		t.Fatalf("fixture %s status %d, want %d", path, v.StatusCode, want)
	}
	if want == http.StatusNoContent || want == http.StatusForbidden {
		return nil
	}
	var out map[string]any
	if json.NewDecoder(io.LimitReader(v.Body, 32768)).Decode(&out) != nil {
		t.Fatal("fixture response invalid")
	}
	return out
}

func tlsBridge(t *testing.T, endpoint string) *httptest.Server {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	p := httputil.NewSingleHostReverseProxy(u)
	p.Transport = &http.Transport{Proxy: nil}
	s := httptest.NewTLSServer(p)
	t.Cleanup(s.Close)
	return s
}

type output struct {
	bytes.Buffer
	calls       int
	revokeAfter int
}

func (o *output) Send(ctx context.Context, b []byte) error {
	if o.revokeAfter > 0 && o.calls >= o.revokeAfter {
		return errors.New("synthetic authority revoked")
	}
	o.calls++
	_, err := o.Write(b)
	return err
}

func TestContextStorageWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run make context-integration for owned real-service fixtures")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture file unavailable")
	}
	var f fixture
	if json.Unmarshal(b, &f) != nil || len(f.Clusters) != 2 {
		t.Fatal("invalid fixture")
	}
	clear(b)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	request(t, f.KMS, "synthetic-root", "sys/mounts/transit", map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", "transit/keys/evidence", map[string]any{"type": "aes256-gcm96"}, 200)
	tokens := map[string]string{}
	for name, operation := range map[string]string{"writer": "encrypt", "reader": "decrypt"} {
		policy := `path "transit/` + operation + `/evidence" { capabilities = ["update"] }`
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+name, map[string]any{"policy": policy}, 204)
		v := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{name}, "no_default_policy": true, "ttl": "15m"}, 200)
		tokens[name] = v["auth"].(map[string]any)["client_token"].(string)
	}
	kmsTLS, s3TLS := tlsBridge(t, f.KMS), tlsBridge(t, f.S3)
	sealer, err := kms.NewSealer(kmsTLS.URL, tokens["writer"], "transit", "evidence", kmsTLS.Client())
	if err != nil {
		t.Fatal(err)
	}
	opener, err := kms.NewOpener(kmsTLS.URL, tokens["reader"], "transit", "evidence", kmsTLS.Client())
	if err != nil {
		t.Fatal(err)
	}
	credential := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &s3TLS.URL, UsePathStyle: true, Credentials: credential, HTTPClient: s3TLS.Client(), RetryMaxAttempts: 1})
	_, err = admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("evidence")})
	if err != nil {
		t.Fatal("fixture bucket creation")
	}
	store, err := objectstore.New(s3TLS.URL, "us-east-1", "evidence", credential, s3TLS.Client())
	if err != nil {
		t.Fatal(err)
	}
	for index, cluster := range f.Clusters {
		t.Run([]string{"cluster-a", "cluster-b"}[index], func(t *testing.T) {
			config, err := clientcmd.BuildConfigFromFlags("", cluster.Config)
			if err != nil {
				t.Fatal("fixture kube config")
			}
			config = rest.CopyConfig(config)
			config.BearerToken = cluster.Token
			config.BearerTokenFile = ""
			config.CertData = nil
			config.KeyData = nil
			config.CertFile = ""
			config.KeyFile = ""
			collector, err := kube.NewContextClient(config)
			if err != nil {
				t.Fatal(err)
			}
			binding := artifact.Binding{ClusterID: "00000000-0000-4000-8000-000000000001", ArtifactID: []string{"00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003"}[index], AttemptID: "00000000-0000-4000-8000-000000000004", MediaType: "application/json"}
			binding.ClusterID = []string{"00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000005"}[index]
			encoder, err := framed.Prepare(ctx, binding, sealer)
			if err != nil {
				t.Fatal(err)
			}
			manifestWriter, err := framed.PrepareManifest(ctx, binding, sealer)
			if err != nil {
				t.Fatal(err)
			}
			targetConfig := rest.CopyConfig(config)
			targetConfig.BearerToken = cluster.TargetToken
			observer, err := kube.NewPermissionClient(targetConfig, binding.ClusterID, cfg.NamespaceRef{Name: cluster.Pod.Namespace, UID: cluster.Pod.NamespaceUID}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			resolver, err := kube.NewPodTargets(observer)
			if err != nil {
				t.Fatal(err)
			}
			selection := targets.Request{ClusterID: binding.ClusterID, Namespace: cfg.NamespaceRef{Name: cluster.Pod.Namespace, UID: cluster.Pod.NamespaceUID}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "fixture", UID: cluster.WorkloadUID}, PodName: cluster.Pod.Name, PodUID: cluster.Pod.UID}
			resolved, err := resolver.ResolvePod(ctx, selection)
			if err != nil || resolved.Pin != cluster.Pod || resolved.NodeUID != cluster.NodeUID || resolved.NodeBootID != cluster.NodeBootID || !resolved.Valid(time.Now()) {
				t.Fatalf("real owner/node resolution: %v", err)
			}
			replaced := selection
			replaced.Workload.UID = "replacement"
			if _, err = resolver.ResolvePod(ctx, replaced); !errors.Is(err, targets.ErrChanged) {
				t.Fatalf("root substitution accepted: %v", err)
			}
			limitedObserver, err := kube.NewPermissionClient(config, binding.ClusterID, selection.Namespace, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			limitedResolver, err := kube.NewPodTargets(limitedObserver)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = limitedResolver.ResolvePod(ctx, selection); !errors.Is(err, targets.ErrDenied) {
				t.Fatalf("collector credential gained owner/node reads: %v", err)
			}
			native, err := collector.Capture(ctx, resolved.Pin)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"MUST-NOT-LEAK", "SYNTHETIC_SECRET", "annotations", "containerNames", "image", "env"} {
				if bytes.Contains(native, []byte(forbidden)) {
					t.Fatalf("projection leaked %s", forbidden)
				}
			}
			var decoded map[string]any
			if json.Unmarshal(native, &decoded) != nil || decoded["ready"] != "True" || decoded["phase"] != "Running" {
				t.Fatal("unusable live pod context")
			}
			var data, pages bytes.Buffer
			layout, err := encoder.Encode(ctx, bytes.NewReader(native), &data, &pages, 4096)
			if err != nil {
				t.Fatal(err)
			}
			prefix := "v1/" + binding.ClusterID + "/" + binding.ArtifactID + "/" + binding.AttemptID + "/"
			d, err := store.PutSmall(ctx, prefix+"data", data.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			i, err := store.PutSmall(ctx, prefix+"index", pages.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.PutSmall(ctx, prefix+"data", data.Bytes()); !errors.Is(err, objectstore.ErrExists) {
				t.Fatalf("conditional creation not enforced: %v", err)
			}
			if err := store.Verify(ctx, d); err != nil {
				t.Fatal(err)
			}
			if err := store.Verify(ctx, i); err != nil {
				t.Fatal(err)
			}
			metadata, err := framed.MarshalLayout(layout)
			if err != nil {
				t.Fatal(err)
			}
			cipher, key, err := manifestWriter.Seal(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			m, err := store.PutSmall(ctx, prefix+"manifest", cipher)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Verify(ctx, m); err != nil {
				t.Fatal(err)
			}
			// New role/client instance, no retained writer key handles used to read.
			freshOpener, err := kms.NewOpener(kmsTLS.URL, tokens["reader"], "transit", "evidence", kmsTLS.Client())
			if err != nil {
				t.Fatal(err)
			}
			ms, err := store.Pin(m)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := ms.ReadRange(ctx, 0, m.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := framed.OpenManifest(ctx, binding, freshOpener, key, stored, m.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := framed.ParseLayout(opened, binding)
			if err != nil {
				t.Fatal(err)
			}
			ds, err := store.Pin(d)
			if err != nil {
				t.Fatal(err)
			}
			is, err := store.Pin(i)
			if err != nil {
				t.Fatal(err)
			}
			r, err := framed.Open(ctx, restored, freshOpener, ds, is)
			if err != nil {
				t.Fatal(err)
			}
			out := &output{}
			if err := r.Read(ctx, 0, layout.NativeBytes, out); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), native) || artifact.Digest(sha256.Sum256(out.Bytes())) != layout.NativeSHA256 {
				t.Fatal("native JSON changed")
			}
			out = &output{}
			if err := r.Read(ctx, 17, 29, out); err != nil || !bytes.Equal(out.Bytes(), native[17:46]) {
				t.Fatalf("native range: %v", err)
			}
			changed := cluster.Pod
			changed.UID = "different-pod"
			if _, err := collector.Capture(ctx, changed); !errors.Is(err, kube.ErrTargetChanged) {
				t.Fatalf("replacement pod: %v", err)
			}
			changed = cluster.Pod
			changed.Namespace = "kube-system"
			if _, err := collector.Capture(ctx, changed); !errors.Is(err, kube.ErrContextDenied) {
				t.Fatalf("foreign namespace: %v", err)
			}
			if _, err := opener.Open(ctx, layout.DataKey, []byte("wrong-binding")); !errors.Is(err, artifact.ErrIntegrity) {
				t.Fatalf("KMS binding substitution: %v", err)
			}
			request(t, f.KMS, tokens["writer"], "transit/decrypt/evidence", map[string]any{"ciphertext": layout.DataKey.Ciphertext}, 403)
			request(t, f.KMS, tokens["reader"], "transit/encrypt/evidence", map[string]any{"plaintext": base64.StdEncoding.EncodeToString([]byte("synthetic"))}, 403)
			t.Logf("nativeBytes=%d dataBytes=%d indexBytes=%d wrappedMetadataBytes=%d; exact JSON and range verified; readonly pod scope and wrap/unwrap role denials verified", len(native), d.Bytes, i.Bytes, m.Bytes)
		})
	}
	// Revoke the collector credential at the real KMS: no key preparation can
	// succeed thereafter. No acquisition is attempted after this failed prepare.
	request(t, f.KMS, "synthetic-root", "auth/token/revoke", map[string]any{"token": tokens["writer"]}, 204)
	_, err = framed.Prepare(ctx, artifact.Binding{ClusterID: "00000000-0000-4000-8000-000000000001", ArtifactID: "00000000-0000-4000-8000-000000000002", AttemptID: "00000000-0000-4000-8000-000000000004", MediaType: "application/json"}, sealer)
	if !errors.Is(err, kms.ErrKeyService) {
		t.Fatalf("revoked KMS prepare: %v", err)
	}
	if strings.Contains(err.Error(), tokens["writer"]) {
		t.Fatal("error leaked credential")
	}
}
