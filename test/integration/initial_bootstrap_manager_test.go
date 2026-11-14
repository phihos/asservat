package integration

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Explicit synthetic protected seed only. SQL role creation, original SCRAM,
// migrations, purpose roles, encrypted audit, activation, history ACL transfer
// and session termination below are actual service operations. Native bootstrap
// guard/UID provenance and original-Pod handover require their separate fixture.
type syntheticManagerRoot struct {
	mu                  sync.Mutex
	state               contracts.InitialBootstrapState
	claims, completions int
	loseCompletion      bool
}

func (r *syntheticManagerRoot) snapshot() contracts.InitialBootstrapState {
	b, _ := json.Marshal(r.state)
	defer clear(b)
	var s contracts.InitialBootstrapState
	_ = json.Unmarshal(b, &s)
	return s
}
func (r *syntheticManagerRoot) ClaimBootstrapSQLManager(ctx context.Context, oid uint32, start time.Time) (contracts.InitialBootstrapState, bool, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.InitialBootstrapState{}, false, time.Time{}, cfg.ErrUnavailable
	}
	fresh := r.state.Manager == nil
	if fresh {
		n := time.Now().UTC().Truncate(time.Microsecond)
		r.state.Manager = &contracts.InitialBootstrapManager{OperationID: custodyID(), StartedAt: n, Until: n.Add(30 * time.Minute), DatabaseOID: oid, PostmasterAt: start}
		r.claims++
	}
	return r.snapshot(), fresh, time.Now().Add(5 * time.Second), nil
}
func (r *syntheticManagerRoot) ReadBootstrapSQLManager(ctx context.Context) (contracts.InitialBootstrapState, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.InitialBootstrapState{}, time.Time{}, cfg.ErrUnavailable
	}
	return r.snapshot(), time.Now().Add(5 * time.Second), nil
}
func (r *syntheticManagerRoot) CompleteBootstrapSQLManager(ctx context.Context, s contracts.InitialBootstrapState, until time.Time, pin contracts.InitialSQLHistoryManager) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil || !time.Now().Before(until) || r.state.Manager.OperationID != s.Manager.OperationID {
		return cfg.ErrUnavailable
	}
	r.state.Manager.Receipt = &pin
	r.completions++
	if r.loseCompletion {
		r.loseCompletion = false
		return cfg.ErrUnavailable
	}
	return nil
}

func initialBootstrapAuditObjects(t *testing.T, ctx context.Context, f fixture) *objectstore.InitialInstallationObjects {
	t.Helper()
	name := "bootstrap-" + strings.ReplaceAll(custodyID(), "-", "")
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+name, map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", name+"/keys/audit", map[string]any{"type": "aes256-gcm96"}, 200)
	tokens := map[string]string{}
	for _, op := range []string{"encrypt", "decrypt"} {
		policy := name + "-" + op
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+policy, map[string]any{"policy": `path "` + name + `/` + op + `/audit" { capabilities=["update"] }`}, 204)
		tokens[op] = request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{policy}, "no_default_policy": true, "ttl": "15m"}, 200)["auth"].(map[string]any)["client_token"].(string)
	}
	key := tlsBridge(t, f.KMS)
	seal, e := kms.NewSealer(key.URL, tokens["encrypt"], name, "audit", key.Client())
	if e != nil {
		t.Fatal(e)
	}
	open, e := kms.NewOpener(key.URL, tokens["decrypt"], name, "audit", key.Client())
	if e != nil {
		t.Fatal(e)
	}
	bridge := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
	if _, e = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &name}); e != nil {
		t.Fatal(e)
	}
	store, e := objectstore.New(bridge.URL, "us-east-1", name, creds, bridge.Client())
	if e != nil {
		t.Fatal(e)
	}
	return &objectstore.InitialInstallationObjects{Store: store, Seal: seal, Open: open}
}
