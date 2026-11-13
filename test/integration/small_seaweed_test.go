package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const smallSeaweedImage = "chrislusf/seaweedfs@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0"
const smallSeaweedInstallation = "66000000-0000-4000-8000-000000000001"
const smallSeaweedCluster = "66000000-0000-4000-8000-000000000002"
const smallSeaweedBucket = "synthetic-small-seaweed"

func smallSeaweedFailureStep(err error) string {
	var named interface{ FixedStep() string }
	if errors.As(err, &named) {
		return named.FixedStep()
	}
	var response interface{ HTTPStatusCode() int }
	if errors.As(err, &response) {
		return "http-" + strconv.Itoa(response.HTTPStatusCode())
	}
	return "unavailable"
}

// One exact backend, synthetic component authority and a finite byte budget.
// No SQL permit/root activation, public request, trial capture or product grant
// is fabricated. The external driver owns names, network, files and cleanup.
func TestSmallSeaweedBackendWithRealS3(t *testing.T) {
	network, name, work := os.Getenv("ASSERVAT_SMALL_SEAWEED_NETWORK"), os.Getenv("ASSERVAT_SMALL_SEAWEED_CONTAINER"), os.Getenv("ASSERVAT_SMALL_SEAWEED_WORK")
	if network == "" && name == "" && work == "" {
		t.Skip("use the owned small Seaweed component driver")
	}
	if !strings.HasPrefix(network, "asservat-small-seaweed-") || name != network+"-s3" || !filepath.IsAbs(work) || !strings.Contains(work, "/.cache/asservat-build/") {
		t.Fatal("invalid owned component scope")
	}
	ctx, end := context.WithTimeout(t.Context(), 3*time.Minute)
	defer end()
	docker := func(input []byte, args ...string) ([]byte, error) {
		call, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(call, "docker", args...)
		cmd.Stdin = bytes.NewReader(input)
		return cmd.CombinedOutput()
	}
	mustDocker := func(args ...string) []byte {
		t.Helper()
		raw, e := docker(nil, args...)
		if e != nil {
			t.Fatalf("owned Docker stage %s failed: %v", args[0], e)
		}
		return raw
	}
	var networks []struct{ Labels map[string]string }
	if json.Unmarshal(mustDocker("network", "inspect", network), &networks) != nil || len(networks) != 1 || networks[0].Labels["asservat.test"] != network {
		t.Fatal("network is not owned")
	}
	plan := contracts.SmallSeaweedPlan{Format: contracts.SmallSeaweedFormat, Namespace: "component", Name: "trial", Image: smallSeaweedImage}
	material, e := kube.BuildSmallSeaweedMaterial(plan, time.Now())
	if e != nil {
		t.Fatal("production initial material", e)
	}
	defer func() {
		for _, raw := range material {
			clear(raw)
		}
	}()
	var admin contracts.SeaweedCredential
	if json.Unmarshal(material[contracts.SmallSeaweedAdminKey], &admin) != nil {
		t.Fatal("administrator material")
	}
	credential := func(purpose, scope string) contracts.SeaweedCredential {
		t.Helper()
		v, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: scope})
		if e != nil {
			t.Fatal("scoped material", e)
		}
		return v
	}
	audit := credential("initial-audit", smallSeaweedInstallation)
	writer := credential("regional-write", smallSeaweedCluster)
	reader := credential("publisher-read", smallSeaweedInstallation)
	cleaner := credential("evidence-delete", smallSeaweedInstallation)
	grant := func(c contracts.SeaweedCredential) contracts.SeaweedGrant {
		return contracts.SeaweedGrant{Credential: c, Bucket: smallSeaweedBucket, InstallationID: smallSeaweedInstallation, ClusterID: smallSeaweedCluster}
	}
	first, e := providerconfig.CompileSeaweedStorage(admin, []contracts.SeaweedGrant{grant(audit)})
	if e != nil {
		t.Fatal("initial IAM", e)
	}
	defer clear(first.Config)
	full, e := providerconfig.CompileSeaweedStorage(admin, []contracts.SeaweedGrant{grant(audit), grant(writer), grant(reader), grant(cleaner)})
	if e != nil {
		t.Fatal("complete IAM", e)
	}
	defer clear(full.Config)
	for _, dir := range []string{"tls", "iam", "filer", "data"} {
		mode := os.FileMode(0755)
		if dir == "data" {
			mode = 0777
		}
		if e = os.MkdirAll(filepath.Join(work, dir), mode); e != nil {
			t.Fatal("private component directory")
		}
		if e = os.Chmod(filepath.Join(work, dir), mode); e != nil {
			t.Fatal("component directory mode")
		}
	}
	writeFile := func(dir, key string, raw []byte) {
		t.Helper()
		if e = os.WriteFile(filepath.Join(work, dir, key), raw, 0444); e != nil {
			t.Fatal("private component file")
		}
	}
	writeFile("tls", "tls.crt", material["tls.crt"])
	writeFile("tls", "tls.key", material["tls.key"])
	writeFile("iam", "s3.json", first.Config)
	writeFile("filer", "filer.toml", []byte("[leveldb2]\nenabled = true\ndir = \"/data/filerldb2\"\n"))
	create := []string{"create", "--name", name, "--label", "asservat.test=" + network, "--network", network, "--user", "65532:65532", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "768m", "--cpus", "2", "--pids-limit", "128", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m"}
	for _, m := range []struct {
		dir, target string
		ro          bool
	}{{"tls", "/run/asservat/objectstore-tls", true}, {"iam", "/run/asservat/objectstore-iam", true}, {"filer", "/etc/seaweedfs", true}, {"data", "/data", false}} {
		mount := "type=bind,src=" + filepath.Join(work, m.dir) + ",dst=" + m.target
		if m.ro {
			mount += ",readonly"
		}
		create = append(create, "--mount", mount)
	}
	create = append(create, "--entrypoint", "/usr/bin/weed", smallSeaweedImage)
	create = append(create, providerconfig.SeaweedServerArgs()...)
	mustDocker(create...)
	mustDocker("start", name)
	var containers []struct {
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
		}
		Image string
	}
	if json.Unmarshal(mustDocker("inspect", name), &containers) != nil || len(containers) != 1 {
		t.Fatal("owned container observation")
	}
	ip := containers[0].NetworkSettings.Networks[network].IPAddress
	if net.ParseIP(ip) == nil {
		t.Fatal("owned backend IP unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(material["ca.crt"]) {
		t.Fatal("generated CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort(plan.Host(), "8333") {
			return nil, errors.New("foreign component endpoint")
		}
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip, "8333"))
	}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("no redirect") }}
	client := func(c contracts.SeaweedCredential) *s3.Client {
		return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(plan.Endpoint()), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, ""), HTTPClient: httpClient, RetryMaxAttempts: 1})
	}
	adminClient := client(admin)
	until := time.Now().Add(40 * time.Second)
	for {
		_, e = adminClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		if e == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("backend authenticated startup unavailable")
		}
		select {
		case <-ctx.Done():
			t.Fatal("backend startup deadline")
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Log("stage=tls-startup-ready")

	response, anonymousErr := httpClient.Get(plan.Endpoint() + "/")
	if anonymousErr != nil {
		t.Fatal("authenticated backend lost verified TLS")
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("anonymous TLS request was not refused")
	}

	plain := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	response, e = plain.Get("http://" + net.JoinHostPort(ip, "8333") + "/")
	if e == nil {
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("plaintext HTTP accepted")
		}
	}
	for _, port := range []string{"9333", "19333", "8888", "18888", "8080", "18080"} {
		conn, e := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 300*time.Millisecond)
		if e == nil {
			conn.Close()
			t.Fatalf("internal provider listener exposed on port %s", port)
		}
	}
	setup, e := objectstore.NewSeaweedSetup(plan.Endpoint(), "us-east-1", admin, httpClient)
	if e != nil {
		t.Fatal("setup constructor", e)
	}
	defer setup.Close()
	claim := contracts.SeaweedBucketInitialization{InstallationID: smallSeaweedInstallation, Bucket: smallSeaweedBucket}
	if e = setup.ConfigureBucket(ctx, claim, first.Policies[smallSeaweedBucket]); e != nil {
		t.Fatalf("initial owned bucket setup: %s", smallSeaweedFailureStep(e))
	}
	if e = setup.ConfigureBucket(ctx, claim, first.Policies[smallSeaweedBucket]); e != nil {
		t.Fatalf("exact owned bucket replay: %s", smallSeaweedFailureStep(e))
	}
	foreign := claim
	foreign.InstallationID = "66000000-0000-4000-8000-000000000009"
	if e = setup.ConfigureBucket(ctx, foreign, first.Policies[smallSeaweedBucket]); e == nil {
		t.Fatal("foreign installation adopted bucket")
	}
	t.Log("stage=ownership-versioning-policy-ready")
	store := func(c contracts.SeaweedCredential) *objectstore.Store {
		t.Helper()
		s, e := objectstore.NewVersionedAudit(plan.Endpoint(), "us-east-1", smallSeaweedBucket, credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, ""), httpClient)
		if e != nil {
			t.Fatal("scoped storage constructor", e)
		}
		t.Cleanup(s.Close)
		return s
	}
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	auditKey := "initial-installation/v1/" + smallSeaweedInstallation + "/component-intent"
	auditStore := store(audit)
	original, e := auditStore.PutSmall(ctx, auditKey, payload)
	if e != nil || original.VersionID == "" || original.VersionID == "null" {
		t.Fatalf("actual scoped initial audit immutable write: %s", smallSeaweedFailureStep(e))
	}
	if _, e = auditStore.PutSmall(ctx, auditKey, payload); !errors.Is(e, objectstore.ErrExists) {
		t.Fatal("conditional immutable duplicate accepted", e)
	}
	exact := func(c contracts.SeaweedCredential, o objectstore.Object) {
		t.Helper()
		// Match the actual encrypted native reader's transport and original deadline,
		// including its existing 30s HTTP bound. A metadata-only readiness response
		// does not prove volume topology is already available after restart.
		source, e := store(c).Pin(o)
		if e != nil {
			t.Fatal("version-pinned source rejected")
		}
		started := time.Now()
		raw, e := source.ReadRange(ctx, 0, o.Bytes)
		if e != nil {
			t.Fatalf("version-pinned production read failed after %.3fs: class=%s contextDone=%t", time.Since(started).Seconds(), smallSeaweedFailureStep(e), ctx.Err() != nil)
		}
		defer clear(raw)
		if !bytes.Equal(raw, payload) {
			t.Fatal("stored exact bytes changed")
		}
	}
	exact(audit, original)
	denied := func(stage string, e error) {
		t.Helper()
		var status interface{ HTTPStatusCode() int }
		if !errors.As(e, &status) || status.HTTPStatusCode() != 403 {
			var code interface{ ErrorCode() string }
			detail := "non-http"
			if errors.As(e, &code) {
				detail = code.ErrorCode()
			}
			t.Fatalf("expected exact403 at %s, class=%s", stage, detail)
		}
	}
	_, e = client(audit).ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(smallSeaweedBucket)})
	denied("audit-list", e)
	_, e = client(audit).PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: aws.String("v1/foreign"), Body: bytes.NewReader(payload)})
	denied("audit-foreign-write", e)
	_, e = client(writer).PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: aws.String("v1/" + smallSeaweedCluster + "/before-reload"), Body: bytes.NewReader(payload)})
	denied("unloaded-credential", e)
	if e = setup.ConfigureBucket(ctx, claim, full.Policies[smallSeaweedBucket]); e != nil {
		t.Fatalf("retained policy extension: %s", smallSeaweedFailureStep(e))
	}
	// The chart restarts SeaweedFS on an IAM Secret change; the test signals
	// the running process after replacing the mounted file.
	next := filepath.Join(work, "iam", "next.json")
	if e = os.WriteFile(next, full.Config, 0444); e != nil {
		t.Fatal("next private IAM")
	}
	if e = os.Rename(next, filepath.Join(work, "iam", "s3.json")); e != nil {
		t.Fatal("atomic private IAM projection")
	}
	if raw, e := docker(nil, "exec", name, "/bin/kill", "-HUP", "1"); e != nil {
		clear(raw)
		t.Fatal("IAM reload signal failed")
	}
	// SIGHUP is asynchronous. Bounded read-only signed metadata requests confirm
	// the new reader is loaded before issuing the one fixture-owned scoped write.
	until = time.Now().Add(5 * time.Second)
	for {
		_, e = client(reader).HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: aws.String("v1/" + smallSeaweedCluster + "/not-created")})
		var status interface{ HTTPStatusCode() int }
		if errors.As(e, &status) && status.HTTPStatusCode() == 404 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("new ordinary read credential not loaded")
		}
		select {
		case <-ctx.Done():
			t.Fatal("IAM observation deadline")
		case <-time.After(100 * time.Millisecond):
		}
	}
	regionalKey := "v1/" + smallSeaweedCluster + "/component-output"
	regional, e := store(writer).PutSmall(ctx, regionalKey, payload)
	if e != nil {
		t.Fatalf("newly loaded ordinary scoped write failed: %s", smallSeaweedFailureStep(e))
	}
	exact(reader, regional)
	t.Log("stage=actual-ordinary-credential-reload-and-write")
	_, e = client(writer).GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: &regional.Key})
	denied("writer-read", e)
	_, e = client(writer).ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(smallSeaweedBucket), Prefix: aws.String("v1/" + smallSeaweedCluster + "/")})
	denied("writer-list", e)
	_, e = client(writer).PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: aws.String("v1/66000000-0000-4000-8000-000000000003/foreign"), Body: bytes.NewReader(payload)})
	denied("writer-other-cluster", e)
	_, e = client(writer).DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: &regional.Key, VersionId: &regional.VersionID})
	denied("writer-delete-version", e)
	_, e = client(reader).PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: &regional.Key, Body: bytes.NewReader(payload)})
	denied("reader-write", e)
	_, e = client(reader).DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: &regional.Key, VersionId: &regional.VersionID})
	denied("reader-delete", e)

	_, e = client(reader).ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(smallSeaweedBucket), Prefix: aws.String("v1/")})
	denied("reader-list", e)
	_, e = client(reader).GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: &original.Key})
	denied("reader-audit-read", e)
	_, e = client(audit).GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: &regional.Key})
	denied("audit-evidence-read", e)
	_, e = client(writer).DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: &regional.Key})
	denied("writer-delete-current", e)

	_, e = client(cleaner).GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: &regional.Key})
	denied("cleaner-read", e)
	_, e = client(cleaner).PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: &regional.Key, Body: bytes.NewReader(payload)})
	denied("cleaner-write", e)
	_, e = client(cleaner).ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(smallSeaweedBucket), Prefix: aws.String("v1/")})
	if e != nil {
		t.Fatal("cleaner exact evidence inventory refused")
	}
	_, e = client(cleaner).ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(smallSeaweedBucket), Prefix: aws.String("initial-installation/")})
	denied("cleaner-foreign-inventory", e)
	for _, c := range []contracts.SeaweedCredential{audit, writer, reader, cleaner} {
		_, e = client(c).PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(smallSeaweedBucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusSuspended}})
		denied(c.Principal.Purpose+"-versioning", e)
		policy := string(full.Policies[smallSeaweedBucket])
		_, e = client(c).PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: aws.String(smallSeaweedBucket), Policy: &policy})
		denied(c.Principal.Purpose+"-policy", e)
		_, e = client(c).PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String(smallSeaweedBucket), Tagging: &s3types.Tagging{TagSet: []s3types.Tag{{Key: aws.String("foreign"), Value: aws.String("refuse")}}}})
		denied(c.Principal.Purpose+"-tags", e)
	}
	toDelete, e := store(writer).PutSmall(ctx, "v1/"+smallSeaweedCluster+"/delete-fixture", payload)
	if e != nil {
		t.Fatal("fixture deletion source", e)
	}
	if _, e = client(cleaner).DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: &toDelete.Key, VersionId: &toDelete.VersionID}); e != nil {
		t.Fatal("actual exact version deletion refused")
	}
	_, e = client(cleaner).DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(smallSeaweedBucket), Key: &original.Key, VersionId: &original.VersionID})
	denied("cleaner-audit-delete", e)
	exact(audit, original)
	exact(reader, regional)
	t.Log("stage=scoped-policy-boundaries-ready")
	mustDocker("restart", "--time", "10", name)
	transport.CloseIdleConnections()
	until = time.Now().Add(30 * time.Second)
	for {
		_, e = adminClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		if e == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("retained backend restart unavailable")
		}
		select {
		case <-ctx.Done():
			t.Fatal("retained restart deadline")
		case <-time.After(200 * time.Millisecond):
		}
	}
	if e = setup.ConfigureBucket(ctx, claim, full.Policies[smallSeaweedBucket]); e != nil {
		t.Fatalf("persisted bucket ownership/policy/versioning changed: %s", smallSeaweedFailureStep(e))
	}
	t.Log("stage=restart-metadata-ready-production-data-read-pending")
	exact(audit, original)
	exact(reader, regional)
	t.Log("stage=restart-persisted-versioned-exact-bytes-complete")
}
