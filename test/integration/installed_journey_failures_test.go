package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/client-go/kubernetes"
)

// The S-02 exit failure-state slices (docs/implementation-status.md), each
// against the installed product, as the owned Keycloak user over MCP:
//
// Focus journey-store-failure:
//   - an object-store failure during an accepted capture ends the capture
//     Indeterminate/StorageOutcomeUnconfirmed with its charges retained;
//   - an exhausted workload context reserve refuses request_capture with
//     CapacityUnavailable, including once no capture is in flight.
//
// Focus journey-start-failure:
//   - a lost completion after regional custody commit never repeats collection
//     (ADR-223): one admission/execution/custody attempt, replay names the
//     original capture and its original deadline ends it Indeterminate;
//   - a key-service failure before the start leaves the capture Pending until
//     its original deadline marks it Indeterminate/DeadlineOutcomeUnconfirmed;
//     it never starts afterwards either.
//
// Faults touch only owned fixtures: one scoped bucket-policy statement, one
// exact completion-transition trigger and a network disconnect of the owned
// OpenBao dev container (never a stop: dev mode keeps all keys in memory).
// Nothing weakens authorization, custody or deadlines.

const installedStoreFaultSID = "DenyInstalledJourneyAttemptStore"

// installedStoreFaultPolicy adds one fixture-only Put denial for the regional
// evidence writer of this cluster, scoped to the exact attempt prefix. Every
// existing statement is preserved; acceptance audit (capture-intent/v1/...),
// reads, other principals and other attempts are unchanged.
func installedStoreFaultPolicy(original, bucket, cluster string, loc artifact.Location) (string, error) {
	if loc.Validate() != nil || loc.ClusterID != cluster || len(original) > 64<<10 || bucket == "" {
		return "", errors.New("invalid store fault scope")
	}
	var policy map[string]json.RawMessage
	var statements []map[string]json.RawMessage
	if json.Unmarshal([]byte(original), &policy) != nil || json.Unmarshal(policy["Statement"], &statements) != nil || len(statements) == 0 {
		return "", errors.New("invalid original store policy")
	}
	for _, statement := range statements {
		var sid string
		if json.Unmarshal(statement["Sid"], &sid) == nil && sid == installedStoreFaultSID {
			return "", errors.New("store fault already present")
		}
	}
	raw, _ := json.Marshal(map[string]any{
		"Sid": installedStoreFaultSID, "Effect": "Deny",
		"Principal": map[string]string{"AWS": "arn:aws:iam::000000000000:user/regional-evidence-" + cluster[:8]},
		// Two actions: the fixture store normalizes a single-element Action
		// array into a plain string, which would break the exact arm/restore
		// readback. The writer's store path uses neither tagging nor this
		// prefix while the fault is armed.
		"Action":   []string{"s3:PutObject", "s3:PutObjectTagging"},
		"Resource": "arn:aws:s3:::" + bucket + "/" + loc.Prefix() + "*",
	})
	var deny map[string]json.RawMessage
	_ = json.Unmarshal(raw, &deny)
	statements = append(statements, deny)
	policy["Statement"], _ = json.Marshal(statements)
	out, err := json.Marshal(policy)
	return string(out), err
}

// installedStoreWriteAccess probes one actual PutObject of the regional
// evidence writer. AccessDenied is the sole tolerated transition response;
// another authentication, TLS or transport failure never establishes the
// fault. The probe key is inside the denied attempt prefix, so an armed
// fault writes nothing.
func installedStoreWriteAccess(ctx context.Context, store *s3.Client, bucket, key string, denied bool) (bool, error) {
	_, err := store.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: strings.NewReader("store-fault-probe")})
	var failure smithy.APIError
	accessDenied := errors.As(err, &failure) && failure.ErrorCode() == "AccessDenied"
	if err != nil && !accessDenied {
		return false, err
	}
	return accessDenied == denied, nil
}

func installedStoreWaitDenied(ctx context.Context, store *s3.Client, bucket, key string) error {
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	for {
		ok, err := installedStoreWriteAccess(call, store, bucket, key, true)
		if err != nil || ok {
			return err
		}
		if err := installedJourneyPause(call, 100*time.Millisecond); err != nil {
			return err
		}
	}
}

// installedFailureKMSContainer derives the owned OpenBao dev container and its
// docker network from the fixture's recorded S3 container identity.
func installedFailureKMSContainer(s3Container string) (network, container string, err error) {
	if !strings.HasPrefix(s3Container, "asservat-context-") || !strings.HasSuffix(s3Container, "-s3") {
		return "", "", errors.New("owned S3 container identity missing")
	}
	network = strings.TrimSuffix(s3Container, "-s3")
	return network, network + "-kms", nil
}

// installedFailureKMSConnected disconnects or reconnects the owned OpenBao
// container's only fixture network and verifies the result by inspect. The
// container keeps running throughout: dev mode holds every key in memory, so
// a stop would destroy the fixture's key material instead of failing calls.
func installedFailureKMSConnected(t *testing.T, ctx context.Context, network, container string, connected bool) {
	t.Helper()
	inspect := func() map[string]bool {
		raw, err := installedOutput(ctx, installedDockerTimeout, "docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container)
		if err != nil {
			t.Fatal("owned KMS container inspect", err)
		}
		var networks map[string]json.RawMessage
		if json.Unmarshal(raw, &networks) != nil {
			t.Fatal("owned KMS container networks", string(raw))
		}
		out := map[string]bool{}
		for name := range networks {
			out[name] = true
		}
		return out
	}
	if before := inspect(); before[network] == connected {
		t.Fatal("owned KMS container already in the requested network state", container, network, connected)
	}
	verb := "disconnect"
	if connected {
		verb = "connect"
	}
	if err := installedRun(ctx, installedDockerTimeout, "docker", "network", verb, network, container); err != nil {
		t.Fatal("owned KMS container network", verb, err)
	}
	if after := inspect(); after[network] != connected {
		t.Fatal("owned KMS container network change not observed", container, network, connected)
	}
	t.Logf("installed failure journey: KMS fixture container %s %sed from network %s", container, verb, network)
}

// installedFailureRun carries one failure focus' MCP session and its bounded
// preview/request/resolve/progress exchanges with the installed product.
type installedFailureRun struct {
	t       *testing.T
	ctx     context.Context
	admin   *pgxpool.Pool
	root    string
	cluster string
	session *sdk.ClientSession
	wire    *contracts.InvestigationContracts
	target  map[string]string
	keys    string
}

func (f *installedFailureRun) readReply(callCtx context.Context, name string, arguments any) (installedJourneyEnvelope, error) {
	result, err := f.session.CallTool(callCtx, &sdk.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		return installedJourneyEnvelope{}, err
	}
	reply, err := installedJourneyReply(f.wire, name, result)
	if err != nil {
		f.t.Fatal("installed response contract", name, err)
	}
	return reply, nil
}

func (f *installedFailureRun) call(callCtx context.Context, name string, arguments any, data any) {
	f.t.Helper()
	reply, err := f.readReply(callCtx, name, arguments)
	if err == nil && reply.Status == "ok" {
		if err = installedJourneyDecode(reply.Data, data); err != nil {
			f.t.Fatal("installed response data", name, err)
		}
		return
	}
	f.t.Fatalf("installed %s: %v", name, err)
}

// preview makes one pod-status preview and returns its identity with the
// pre-generated capture/attempt/artifact identities read back from SQL.
func (f *installedFailureRun) preview() (string, artifact.Location, string, time.Time) {
	f.t.Helper()
	var preview struct {
		PreviewID      string `json:"preview_id"`
		CaptureEnabled bool   `json:"capture_enabled"`
		SelectedPods   []struct {
			UID string `json:"uid"`
		} `json:"selected_pods"`
	}
	f.call(f.ctx, "preview_capture", map[string]any{"target_ref": f.target,
		"preset_ref": map[string]string{"name": "pod-status", "version": "v1"}, "requested_retention_seconds": installedJourneyRetentionSeconds()}, &preview)
	if !preview.CaptureEnabled || len(preview.SelectedPods) != 1 || preview.PreviewID == "" {
		f.t.Fatal("installed failure preview did not pin the regional Pod", preview)
	}
	call, end := context.WithTimeout(f.ctx, 10*time.Second)
	defer end()
	var loc artifact.Location
	var captureID string
	var deadline time.Time
	err := f.admin.QueryRow(call, `SELECT capture_id::text, attempt_id::text,
 convert_from(blueprint_json,'UTF8')::jsonb->>'ArtifactID', deadline
FROM context_preview WHERE root_id=$1 AND id=$2`, f.root, preview.PreviewID).Scan(&captureID, &loc.AttemptID, &loc.ArtifactID, &deadline)
	loc.ClusterID = f.cluster
	if err != nil || loc.Validate() != nil || !time.Now().Before(deadline) {
		f.t.Fatal("installed failure preview identities unavailable", err, loc, deadline)
	}
	return preview.PreviewID, loc, captureID, deadline
}

type installedFailureCall struct {
	result *sdk.CallToolResult
	err    error
}

func (f *installedFailureRun) startRequest(previewID, key string) <-chan installedFailureCall {
	replied := make(chan installedFailureCall, 1)
	go func() {
		result, err := f.session.CallTool(f.ctx, &sdk.CallToolParams{Name: "request_capture", Arguments: map[string]any{"preview_id": previewID, "idempotency_key": key}})
		replied <- installedFailureCall{result: result, err: err}
	}()
	return replied
}

// request admits one capture under the original preview and key. A non-empty
// code is the validated public failure code; captureID is set only on ok.
func (f *installedFailureRun) request(previewID, key string) (code, captureID string) {
	f.t.Helper()
	return f.requestReply(<-f.startRequest(previewID, key))
}

func (f *installedFailureRun) requestReply(call installedFailureCall) (code, captureID string) {
	f.t.Helper()
	if call.err != nil {
		f.t.Logf("installed failure request_capture transport: %v", call.err)
		return "OutcomeUnknown", ""
	}
	reply, code, err := installedJourneyReplyCode(f.wire, "request_capture", call.result)
	if err != nil {
		f.t.Fatal("installed response contract request_capture", err)
	}
	if code == "" {
		var current struct {
			CaptureID string `json:"capture_id"`
		}
		if err = installedJourneyDecode(reply.Data, &current); err != nil {
			f.t.Fatal("installed response data request_capture", err)
		}
		captureID = current.CaptureID
	}
	f.t.Logf("installed failure request_capture %s request %s", map[bool]string{true: "ok", false: code}[code == ""], reply.RequestID)
	return code, captureID
}

// resolveAccepted polls the original request's resolution until it reports
// the original capture accepted.
func (f *installedFailureRun) resolveAccepted(previewID, key, captureID string) {
	f.t.Helper()
	call, end := context.WithTimeout(f.ctx, 90*time.Second)
	defer end()
	for {
		reply, err := f.readReply(call, "resolve_capture_request", map[string]any{"preview_id": previewID, "idempotency_key": key})
		if err == nil && reply.Status == "ok" {
			var disposition installedJourneyDisposition
			if err = installedJourneyDecode(reply.Data, &disposition); err != nil {
				f.t.Fatal("installed response data resolve_capture_request", err)
			}
			if disposition.State == "accepted" && disposition.CaptureID == captureID {
				return
			}
			if disposition.State != "accepted" && disposition.State != "pending" {
				f.t.Fatal("installed failure request closed before admission", disposition.State)
			}
		}
		if installedJourneyPause(call, 2*time.Second) != nil {
			f.t.Fatalf("installed failure request %s was not accepted: %v", captureID, err)
		}
	}
}

// progress reads the original capture's public progress; an unavailable read
// is not a state change.
func (f *installedFailureRun) progress(callCtx context.Context, captureID string) (installedJourneyCaptureProgress, bool) {
	f.t.Helper()
	var progress installedJourneyCaptureProgress
	reply, err := f.readReply(callCtx, "get_capture", map[string]string{"capture_id": captureID})
	if err != nil || reply.Status != "ok" {
		return progress, false
	}
	if installedJourneyDecode(reply.Data, &progress) != nil {
		f.t.Fatal("installed status data get_capture")
	}
	if progress.CaptureID != captureID {
		f.t.Fatal("installed progress changed the original capture identity", progress.CaptureID, captureID)
	}
	return progress, true
}

// waitPhase polls until the capture reaches one of the wanted phases and
// returns the observation.
func (f *installedFailureRun) waitPhase(what, captureID string, until time.Time, phases ...string) installedJourneyCaptureProgress {
	f.t.Helper()
	call, end := context.WithDeadline(f.ctx, until)
	defer end()
	for call.Err() == nil {
		if progress, ok := f.progress(call, captureID); ok {
			for _, phase := range phases {
				if progress.Phase == phase {
					return progress
				}
			}
		}
		if installedJourneyPause(call, 2*time.Second) != nil {
			break
		}
	}
	f.t.Fatalf("installed failure journey: timed out waiting for %s (capture %s)", what, captureID)
	return installedJourneyCaptureProgress{}
}

// reasonCode is the first action reason of a terminal progress observation.
func installedFailureReason(progress installedJourneyCaptureProgress) string {
	for _, action := range progress.Actions {
		if action.ReasonCode != "" {
			return action.ReasonCode
		}
	}
	return ""
}

// counts reads the durable admission/execution/custody cardinality of one
// capture: one admission, at most one execution and one custody attempt.
func (f *installedFailureRun) counts(captureID string) (captures, executions, attempts int) {
	f.t.Helper()
	call, end := context.WithTimeout(f.ctx, 10*time.Second)
	defer end()
	err := f.admin.QueryRow(call, `SELECT
 (SELECT count(*) FROM context_capture c WHERE c.root_id=$1 AND c.id=$2::uuid),
 (SELECT count(*) FROM context_execution e WHERE e.root_id=$1 AND e.capture_id=$2::uuid),
 (SELECT count(*) FROM custody_attempt a JOIN context_capture c ON c.attempt_id=a.id WHERE c.root_id=$1 AND c.id=$2::uuid)`,
		f.root, captureID).Scan(&captures, &executions, &attempts)
	if err != nil || captures != 1 {
		f.t.Fatal("installed failure capture cardinality", captures, executions, attempts, err)
	}
	return captures, executions, attempts
}

// qualifyInstalledJourneyFailures runs the S-02 exit failure legs of the
// current focus (journey-store-failure or journey-start-failure).
func qualifyInstalledJourneyFailures(t *testing.T, ctx context.Context, admin *pgxpool.Pool, providers *initialRuntimeNativeProviders, evidenceBucket, root string, identity *installedIdentity, publicRoot []byte, address, origin string, api kubernetes.Interface, hubNamespace, workerDeployment, cluster, namespace, workload string, diagnose func()) {
	t.Helper()
	if identity == nil {
		t.Fatal("installed failure journey requires the harness identity provider")
	}
	cert, err := x509.ParseCertificate(publicRoot)
	if err != nil {
		t.Fatal("public listener root", err)
	}
	identity.initializeProcessing(t, ctx, cert, address, origin, diagnose)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	dial := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial.DialContext(ctx, network, address)
		}}
	defer transport.CloseIdleConnections()
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal("installed wire contracts", err)
	}
	tokens := identity.mcpTokenSource(origin)
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-failure-journey", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, tokens.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal("installed failure MCP session", err)
	}
	defer session.Close()
	run := &installedFailureRun{t: t, ctx: ctx, admin: admin, root: root, cluster: cluster, session: session, wire: wire,
		target: map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		keys:   "installed-" + installedJourneyFocus()}
	switch installedJourneyFocus() {
	case "journey-store-failure":
		run.legStoreUnconfirmed(providers, evidenceBucket)
		run.legCapacityUnavailable()
	case "journey-start-failure":
		run.legCompletionLost()
		run.legKeyServiceDown()
	default:
		t.Fatal("unknown failure focus", installedJourneyFocus())
	}
}

// legStoreUnconfirmed: with one scoped Put denial armed before the request,
// the accepted capture's encrypted store is refused by the object store and
// the capture ends Indeterminate/StorageOutcomeUnconfirmed. Charges are
// retained for the deletion lifecycle; the original policy is exactly
// restored afterwards.
func (f *installedFailureRun) legStoreUnconfirmed(providers *initialRuntimeNativeProviders, evidenceBucket string) {
	f.t.Helper()
	previewID, loc, captureID, _ := f.preview()
	store := s3.New(s3.Options{Region: providers.desired.AuditStore.Region, BaseEndpoint: aws.String(providers.desired.AuditStore.Endpoint), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: providers.client, RetryMaxAttempts: 1})
	setup, end := context.WithTimeout(f.ctx, 30*time.Second)
	defer end()
	fault := &installedDeletionFault{store: store, bucket: evidenceBucket}
	var err error
	fault.original, err = fault.read(setup)
	if err != nil {
		f.t.Fatal("installed store fault: original fixture policy unavailable", err)
	}
	if unexpected, ok := installedDeletionInstalledPolicy(fault.original, installerEvidenceBucketPolicy(evidenceBucket)); !ok {
		f.t.Fatal("installed store fault: unexpected original fixture policy", unexpected)
	}
	fault.denied, err = installedStoreFaultPolicy(fault.original, evidenceBucket, f.cluster, loc)
	if err != nil {
		f.t.Fatal("installed store fault: invalid fault policy", err)
	}
	// Registered before the mutation: Fatal/unknown replies still restore
	// synchronously before this test completes, under a separate finite bound.
	f.t.Cleanup(func() {
		cleanup, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		if err := fault.restore(cleanup); err != nil {
			f.t.Error("installed store fault: original policy cleanup", err)
		}
	})
	if err = fault.arm(setup); err != nil {
		f.t.Fatal("installed store fault: arm", err)
	}
	// The probe uses the fixture's existing regional evidence credential; it
	// creates no user, key or grant, and a denied Put writes nothing.
	regional := s3.New(s3.Options{Region: providers.desired.AuditStore.Region, BaseEndpoint: aws.String(providers.desired.AuditStore.Endpoint), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("regional-evidence-"+f.cluster[:8], "regional-evidence-secret-"+f.cluster[:8], ""), HTTPClient: providers.client, RetryMaxAttempts: 1})
	if err = installedStoreWaitDenied(setup, regional, evidenceBucket, loc.Prefix()+"store-fault-probe"); err != nil {
		f.t.Fatal("installed store fault: denial was not observed with the actual regional credential", err)
	}
	key := f.keys + "-store"
	code, got := f.request(previewID, key)
	if (code != "" && code != "OutcomeUnknown") || (got != "" && got != captureID) {
		f.t.Fatal("installed store fault: unexpected request reply under the armed fault", code, got, captureID)
	}
	f.resolveAccepted(previewID, key, captureID)
	progress := f.waitPhase("the store-unconfirmed capture", captureID, time.Now().Add(3*time.Minute), "Indeterminate")
	if reason := installedFailureReason(progress); reason != "StorageOutcomeUnconfirmed" {
		f.t.Fatal("installed store fault: wrong indeterminate reason", reason)
	}
	if _, executions, attempts := f.counts(captureID); executions != 1 || attempts != 1 {
		f.t.Fatal("installed store fault: capture was repeated or lacks its original attempt", executions, attempts)
	}
	setup2, end2 := context.WithTimeout(f.ctx, 30*time.Second)
	defer end2()
	var phase, state string
	if err = f.admin.QueryRow(setup2, `SELECT e.phase, a.state FROM context_execution e
JOIN context_capture c ON c.root_id=e.root_id AND c.id=e.capture_id
JOIN custody_attempt a ON a.id=c.attempt_id
WHERE e.root_id=$1 AND e.capture_id=$2::uuid`, f.root, captureID).Scan(&phase, &state); err != nil || phase != "storeUnconfirmed" || state == "deleted" {
		f.t.Fatal("installed store fault: durable execution/custody state", phase, state, err)
	}
	if err = fault.restore(setup2); err != nil {
		f.t.Fatal("installed store fault: original policy restoration", err)
	}
	f.t.Logf("installed failure journey: object-store failure during the accepted capture %s ended Indeterminate/StorageOutcomeUnconfirmed; charges retained, policy restored", captureID)
}

// legCapacityUnavailable: repeated admissions against the workload's finite
// context reserve (records survive until the deletion lifecycle) end in a
// CapacityUnavailable refusal that persists once no capture is in flight.
func (f *installedFailureRun) legCapacityUnavailable() {
	f.t.Helper()
	var accepted []string
	refused := false
	for attempt := 1; attempt <= 12 && !refused; attempt++ {
		previewID, _, captureID, _ := f.preview()
		key := fmt.Sprintf("%s-capacity-%d", f.keys, attempt)
		code, got := f.request(previewID, key)
		if code == "CapacityUnavailable" {
			// Distinguish the exhausted reserve from a transient in-flight
			// limit: once every accepted capture is terminal, a fresh request
			// must still be refused.
			until := time.Now().Add(4 * time.Minute)
			for _, id := range accepted {
				f.waitPhase("a terminal in-flight capture", id, until, "Succeeded", "Failed", "Indeterminate", "Cancelled")
			}
			confirmID, _, confirmCapture, _ := f.preview()
			code, _ = f.request(confirmID, key+"-confirm")
			if code == "CapacityUnavailable" {
				refused = true
				continue
			}
			if code != "" {
				f.t.Fatal("installed capacity leg: unexpected refusal", code)
			}
			f.resolveAccepted(confirmID, key+"-confirm", confirmCapture)
			accepted = append(accepted, confirmCapture)
			continue
		}
		if code != "" {
			f.t.Fatal("installed capacity leg: unexpected refusal", code)
		}
		if got != captureID {
			f.t.Fatal("installed capacity leg: admission changed the capture identity", got, captureID)
		}
		f.resolveAccepted(previewID, key, captureID)
		accepted = append(accepted, captureID)
	}
	if !refused {
		f.t.Fatal("installed capacity leg: twelve admissions never exhausted the workload context reserve", len(accepted))
	}
	f.t.Logf("installed failure journey: after %d retained admissions the workload's context reserve refused request_capture CapacityUnavailable with no capture in flight", len(accepted))
}

// legCompletionLost rejects only the hub's durable stored transition after the
// region committed custody. This deterministically exercises the lost-reply
// state (ADR-223) without racing a process kill against a small capture.
// Replay never repeats collection or imports the committed regional result.
func (f *installedFailureRun) legCompletionLost() {
	f.t.Helper()
	previewID, _, captureID, deadline := f.preview()
	dropCompletionFault := func(ctx context.Context) error {
		_, err := f.admin.Exec(ctx, `DROP TRIGGER IF EXISTS fixture_lost_completion ON context_execution; DROP FUNCTION IF EXISTS fixture_lost_completion();`)
		return err
	}
	f.t.Cleanup(func() {
		cleanup, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		if err := dropCompletionFault(cleanup); err != nil {
			f.t.Errorf("installed disconnect leg: restore completion guard: %v", err)
		}
	})
	setup, endSetup := context.WithTimeout(f.ctx, 10*time.Second)
	_, err := f.admin.Exec(setup, fmt.Sprintf(`CREATE FUNCTION fixture_lost_completion() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.root_id='%s'::uuid AND NEW.capture_id='%s'::uuid AND OLD.phase='started' AND NEW.phase='stored' THEN
  RAISE EXCEPTION 'fixture lost regional completion reply' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER fixture_lost_completion BEFORE UPDATE ON context_execution
FOR EACH ROW EXECUTE FUNCTION fixture_lost_completion();`, f.root, captureID))
	endSetup()
	if err != nil {
		f.t.Fatal("installed disconnect leg: install completion loss", err)
	}
	key := f.keys + "-disconnect"
	response := f.startRequest(previewID, key)
	commitWait, endCommit := context.WithTimeout(f.ctx, 60*time.Second)
	defer endCommit()
	for {
		var stored bool
		err := f.admin.QueryRow(commitWait, `SELECT EXISTS(SELECT 1 FROM custody_attempt a JOIN context_capture c ON c.attempt_id=a.id WHERE c.root_id=$1 AND c.id=$2::uuid AND a.state='stored_unpublished')`, f.root, captureID).Scan(&stored)
		if err == nil && stored {
			break
		}
		if installedJourneyPause(commitWait, time.Millisecond) != nil {
			f.t.Fatal("installed disconnect leg: regional completion never committed", err)
		}
	}
	phaseRead, endPhase := context.WithTimeout(f.ctx, 10*time.Second)
	var executionPhase string
	err = f.admin.QueryRow(phaseRead, `SELECT phase FROM context_execution WHERE root_id=$1 AND capture_id=$2::uuid`, f.root, captureID).Scan(&executionPhase)
	endPhase()
	if err != nil {
		f.t.Fatal("installed disconnect leg: execution phase unreadable after completion loss", err)
	}
	if executionPhase != "started" {
		f.t.Fatal("installed disconnect leg: regional completion was recorded despite the fault", executionPhase)
	}
	restore, endRestore := context.WithTimeout(f.ctx, 10*time.Second)
	err = dropCompletionFault(restore)
	endRestore()
	if err != nil {
		f.t.Fatal("installed disconnect leg: remove completion loss", err)
	}
	originalCode, _ := f.requestReply(<-response)
	f.t.Logf("installed disconnect leg: original public operation resolved %s", originalCode)
	// The hub replays the original request passively: same capture, no new
	// admission, execution or attempt.
	f.resolveAccepted(previewID, key, captureID)
	if code, again := f.request(previewID, key); code != "" || again != captureID {
		f.t.Fatal("installed disconnect leg: replayed request did not return the original capture", code, again, captureID)
	}
	if _, executions, attempts := f.counts(captureID); executions > 1 || attempts != 1 {
		f.t.Fatal("installed disconnect leg: collection was repeated after completion loss", executions, attempts)
	}
	deadlineWait, endDeadline := context.WithDeadline(f.ctx, deadline.Add(75*time.Second))
	defer endDeadline()
	for {
		var observed bool
		err := f.admin.QueryRow(deadlineWait, `SELECT deadline_observed_at IS NOT NULL FROM context_capture WHERE root_id=$1 AND id=$2::uuid`, f.root, captureID).Scan(&observed)
		if err == nil && observed {
			break
		}
		if installedJourneyPause(deadlineWait, 2*time.Second) != nil {
			progress, ok := f.progress(f.ctx, captureID)
			f.t.Fatalf("installed disconnect leg: original deadline was never observed (capture %s, progress %+v, readable %t): %v", captureID, progress, ok, err)
		}
	}
	progress := f.waitPhase("a terminal disconnected capture", captureID, time.Now().Add(45*time.Second), "Indeterminate")
	reason := installedFailureReason(progress)
	if reason != "DeadlineOutcomeUnconfirmed" {
		f.t.Fatal("installed disconnect leg: wrong indeterminate reason", reason)
	}
	// One deadline-observer sweep later the outcome and cardinality stand.
	if installedJourneyPause(f.ctx, 40*time.Second) != nil {
		f.t.Fatal("installed disconnect leg: stability wait", f.ctx.Err())
	}
	if _, executions, attempts := f.counts(captureID); executions > 1 || attempts != 1 {
		f.t.Fatal("installed disconnect leg: collection was repeated after the outcome", executions, attempts)
	}
	if after, ok := f.progress(f.ctx, captureID); !ok || after.Phase != progress.Phase {
		f.t.Fatal("installed disconnect leg: terminal outcome changed", progress.Phase, after.Phase)
	}
	f.t.Logf("installed failure journey: capture %s committed regional custody but its completion was not recorded; the result was not imported and the capture resolved Indeterminate (%s) without another collection", captureID, reason)
}

// legKeyServiceDown disconnects the owned OpenBao container after the public
// operation's audited Begin but before its capture-intent seal. Admission can
// then commit, while the intent cannot be sealed and no execution starts. The
// capture stays Pending after KMS recovery until its original deadline marks it
// Indeterminate/DeadlineOutcomeUnconfirmed (ADR-223). Dev mode keeps all keys
// in memory, so the container is never stopped.
func (f *installedFailureRun) legKeyServiceDown() {
	f.t.Helper()
	raw, err := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if err != nil {
		f.t.Fatal("owned fixture identities unavailable", err)
	}
	var fixtures struct {
		Container string `json:"runtimeProviderPairS3Container"`
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		f.t.Fatal("owned fixture identities", err)
	}
	clear(raw)
	network, container, err := installedFailureKMSContainer(fixtures.Container)
	if err != nil {
		f.t.Fatal(err)
	}
	previewID, _, captureID, deadline := f.preview()
	disconnected := false
	f.t.Cleanup(func() {
		if !disconnected {
			return
		}
		cleanup, end := context.WithTimeout(context.Background(), installedDockerTimeout)
		defer end()
		installedFailureKMSConnected(f.t, cleanup, network, container, true)
	})
	response := f.startRequest(previewID, f.keys+"-keyservice")
	begin, endBegin := context.WithTimeout(f.ctx, 10*time.Second)
	defer endBegin()
	for {
		var begun bool
		err = f.admin.QueryRow(begin, `SELECT EXISTS(
 SELECT 1 FROM operation_audit a JOIN context_preview p ON p.root_id=a.root_id
 WHERE a.root_id=$1 AND p.id=$2::uuid AND a.intent->>'Name'='request_capture'
 AND (a.intent->>'CreatedAt')::timestamptz>=p.created_at AND a.intent_receipt IS NOT NULL)`, f.root, previewID).Scan(&begun)
		if err != nil {
			f.t.Fatal("installed key-service leg: public operation Begin unavailable", err)
		}
		if begun {
			break
		}
		select {
		case call := <-response:
			code, got := f.requestReply(call)
			f.t.Fatal("installed key-service leg: request completed before the Begin gate", code, got)
		default:
		}
		if installedJourneyPause(begin, 5*time.Millisecond) != nil {
			f.t.Fatal("installed key-service leg: public operation Begin was not acknowledged")
		}
	}
	installedFailureKMSConnected(f.t, f.ctx, network, container, false)
	disconnected = true
	code, _ := f.requestReply(<-response)
	f.t.Logf("installed key-service leg: request replied %s after its audited Begin with the key service disconnected", map[bool]string{true: "ok", false: code}[code == ""])
	// Admission committed before the intent's key sealing: the durable capture
	// exists and stays Pending without an execution. Outlast the bounded write.
	settle, endSettle := context.WithTimeout(f.ctx, 40*time.Second)
	defer endSettle()
	for {
		var audited bool
		if err = f.admin.QueryRow(settle, `SELECT state='intent_audited' FROM context_capture WHERE root_id=$1 AND id=$2::uuid`, f.root, captureID).Scan(&audited); err != nil {
			f.t.Fatal("installed key-service leg: admission was not durable", err)
		}
		if audited {
			f.t.Fatal("installed key-service leg: intent was audited without the key service")
		}
		if settle.Err() != nil {
			break
		}
		if installedJourneyPause(settle, 2*time.Second) != nil {
			break
		}
	}
	if _, executions, attempts := f.counts(captureID); executions != 0 || attempts != 1 {
		f.t.Fatal("installed key-service leg: capture started or lost its original charge", executions, attempts)
	}
	installedFailureKMSConnected(f.t, f.ctx, network, container, true)
	disconnected = false
	f.waitPhase("the still-pending capture after KMS recovery", captureID, time.Now().Add(30*time.Second), "Pending")
	// Recovery does not continue the failed start. The hub-worker's SQL-only
	// deadline observer marks the original capture at its original deadline.
	deadlineWait, endDeadline := context.WithDeadline(f.ctx, deadline.Add(75*time.Second))
	defer endDeadline()
	for {
		var observed bool
		err = f.admin.QueryRow(deadlineWait, `SELECT deadline_observed_at IS NOT NULL FROM context_capture WHERE root_id=$1 AND id=$2::uuid`, f.root, captureID).Scan(&observed)
		if err == nil && observed {
			break
		}
		if installedJourneyPause(deadlineWait, 5*time.Second) != nil {
			f.t.Fatal("installed key-service leg: original deadline was never observed", err)
		}
	}
	progress := f.waitPhase("the deadline-observed capture", captureID, time.Now().Add(90*time.Second), "Indeterminate")
	if reason := installedFailureReason(progress); reason != "DeadlineOutcomeUnconfirmed" {
		f.t.Fatal("installed key-service leg: wrong indeterminate reason", reason)
	}
	if _, executions, attempts := f.counts(captureID); executions != 0 || attempts != 1 {
		f.t.Fatal("installed key-service leg: capture started after its deadline", executions, attempts)
	}
	f.t.Logf("installed failure journey: key-service failure before the start left capture %s Pending until its original deadline marked it Indeterminate/DeadlineOutcomeUnconfirmed; it never started", captureID)
}

// --- Unit tests for the pure fault helpers (no fixture needed). ---

func TestInstalledStoreFaultPolicyKeepsOriginalScope(t *testing.T) {
	cluster := "10000000-0000-4000-8000-000000000004"
	loc := artifact.Location{ClusterID: cluster, ArtifactID: "10000000-0000-4000-8000-000000000002", AttemptID: "10000000-0000-4000-8000-000000000003"}
	original := installerEvidenceBucketPolicy("evidence")
	fault, err := installedStoreFaultPolicy(original, "evidence", cluster, loc)
	if err != nil {
		t.Fatal(err)
	}
	var want, got struct{ Statement []map[string]any }
	_ = json.Unmarshal([]byte(original), &want)
	_ = json.Unmarshal([]byte(fault), &got)
	if len(got.Statement) != len(want.Statement)+1 || !reflect.DeepEqual(got.Statement[:len(want.Statement)], want.Statement) {
		t.Fatal("original grants or denials changed")
	}
	deny := got.Statement[len(want.Statement)]
	if deny["Sid"] != installedStoreFaultSID || deny["Effect"] != "Deny" ||
		deny["Resource"] != "arn:aws:s3:::evidence/"+loc.Prefix()+"*" ||
		!reflect.DeepEqual(deny["Principal"], map[string]any{"AWS": "arn:aws:iam::000000000000:user/regional-evidence-" + cluster[:8]}) ||
		!reflect.DeepEqual(deny["Action"], []any{"s3:PutObject", "s3:PutObjectTagging"}) {
		t.Fatal("fault escaped the exact regional writer store scope", deny)
	}
	if _, err := installedStoreFaultPolicy(fault, "evidence", cluster, loc); err == nil {
		t.Fatal("rearmed an existing fault")
	}
	if _, err := installedStoreFaultPolicy(original, "evidence", cluster, artifact.Location{ClusterID: "10000000-0000-4000-8000-000000000009", ArtifactID: loc.ArtifactID, AttemptID: loc.AttemptID}); err == nil {
		// A location without the request's cluster never scopes a denial.
		t.Fatal("accepted a foreign cluster scope")
	}
	if _, err := installedStoreFaultPolicy(original, "evidence", cluster, artifact.Location{}); err == nil {
		t.Fatal("accepted an invalid location")
	}
}

func TestInstalledStoreProbeRequiresActualAccessDenied(t *testing.T) {
	for _, tc := range []struct {
		code             string
		denied, ok, fail bool
	}{
		{"AccessDenied", true, true, false},
		{"AccessDenied", false, false, false},
		{"InvalidAccessKeyId", true, false, true},
		{"ServiceUnavailable", true, false, true},
		{"", true, false, false}, // a successful Put never proves the denial
		{"", false, true, false},
	} {
		t.Run(fmt.Sprintf("%s/%s", map[bool]string{true: "denied", false: "allowed"}[tc.denied], tc.code), func(t *testing.T) {
			h := &http.Client{Transport: installedDeletionProbeTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPut || r.URL.Path != "/evidence/v1/exact-attempt/store-fault-probe" {
					t.Fatal("permission probe escaped the exact attempt store scope", r.Method, r.URL.Path)
				}
				if tc.code == "" {
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"ETag": {`"synthetic"`}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				}
				body := "<Error><Code>" + tc.code + "</Code><Message>synthetic</Message></Error>"
				return &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{"Content-Type": {"application/xml"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			store := s3.New(s3.Options{Region: "synthetic", BaseEndpoint: aws.String("https://synthetic.invalid"), UsePathStyle: true,
				Credentials: credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), HTTPClient: h, RetryMaxAttempts: 1})
			ok, err := installedStoreWriteAccess(t.Context(), store, "evidence", "v1/exact-attempt/store-fault-probe", tc.denied)
			if ok != tc.ok || (err != nil) != tc.fail {
				t.Fatal("wrong store denial qualification", ok, err)
			}
		})
	}
}

func TestInstalledFailureKMSContainerRequiresOwnedIdentity(t *testing.T) {
	network, container, err := installedFailureKMSContainer("asservat-context-abc123-s3")
	if err != nil || network != "asservat-context-abc123" || container != "asservat-context-abc123-kms" {
		t.Fatal("wrong fixture derivation", network, container, err)
	}
	for _, name := range []string{"", "asservat-context-abc123-kms", "other-context-abc-s3", "asservat-context-abc123", "asservat-context-abc123-s3-extra"} {
		if _, _, err := installedFailureKMSContainer(name); err == nil {
			t.Fatal("accepted an unowned fixture identity", name)
		}
	}
}
