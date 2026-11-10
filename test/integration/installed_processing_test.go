package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/transport/browser"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type installedProcessingRun struct {
	SQL                                 *pgxpool.Pool
	RootID                              string
	Identity                            *installedIdentity
	PublicRoot                          *x509.Certificate
	Address, Origin, CaseID, ArtifactID string
	ExpiresAt                           time.Time
	Native                              []byte
	Transport                           http.RoundTripper
	Call                                func(context.Context, string, any) (installedJourneyEnvelope, error)
	Diagnose                            func()
}
type installedProcessingReceipt struct {
	RootID      string `json:"rootID"`
	Epoch       string `json:"epoch"`
	RequestID   string `json:"requestID"`
	RuleID      string `json:"ruleID"`
	OperationID string `json:"operationID"`
	State       string `json:"state"`
	Revision    int64  `json:"revision"`
	Sequence    int64  `json:"sequence"`
}
type installedProcessingEvent struct {
	Kind    string                     `json:"kind"`
	Receipt installedProcessingReceipt `json:"receipt"`
	Input   json.RawMessage            `json:"input"`
	Key     string                     `json:"key"`
	Stage   string                     `json:"stage"`
	Reason  string                     `json:"reason"`
	Check   string                     `json:"check"`
}

// The real compiled React journey owns both mutations and obtains release
// scope/revision only from the durable inventory after a route reload. SQL below
// is an independent observer, never a source of authority or a fixture mutation.
func qualifyInstalledProcessing(t *testing.T, parent context.Context, c installedProcessingRun) {
	t.Helper()
	started := time.Now()
	if !time.Now().Before(c.ExpiresAt) || c.Identity == nil || c.Call == nil || c.Diagnose == nil {
		t.Fatal("installed processing requires original live artifact and public identity")
	}
	ctx, cancel := context.WithDeadline(parent, c.ExpiresAt)
	defer cancel()
	defer func() {
		if t.Failed() {
			c.Diagnose()
		}
	}()
	t.Logf("installed processing stage=start, original artifact access remaining=%s", time.Until(c.ExpiresAt).Round(time.Second))
	session := c.Identity.consoleSession(t, ctx, c.PublicRoot, c.Address, c.Origin)
	driver := startInstalledProcessingBrowser(t, ctx, session, c.Address, c.ArtifactID, c.CaseID)
	next := func(want string) installedProcessingEvent {
		t.Helper()
		var event installedProcessingEvent
		driver.read(&event)
		if event.Kind == "failed" {
			t.Fatalf("installed processing browser stage=%s reason=%s check=%s", event.Stage, event.Reason, event.Check)
		}
		if event.Kind != want {
			t.Fatalf("installed processing expected %s, received %s", want, event.Kind)
		}
		return event
	}
	restriction := next("restricted")
	if restriction.Receipt.State != "restricted" || restriction.Receipt.Revision != 1 {
		t.Fatal("installed processing restriction receipt")
	}
	c.checkReceipt(t, ctx, restriction, "normal")
	c.checkReplay(t, ctx, session, restriction)
	t.Logf("installed processing stage=restricted after %s", time.Since(started).Round(time.Millisecond))
	// These are new ordinary operations by the same signed-in user. Privacy
	// operator membership does not bypass processing on ordinary evidence reads.
	for _, request := range []struct {
		name  string
		input any
	}{
		{"get_case", map[string]string{"case_id": c.CaseID}},
		{"prepare_artifact_download", map[string]string{"artifact_id": c.ArtifactID, "idempotency_key": "installed-processing-blocked-" + c.ArtifactID}},
	} {
		out, err := c.Call(ctx, request.name, request.input)
		if err != nil || out.Status != "error" {
			t.Fatal("restricted evidence accepted a new ordinary read", request.name, err)
		}
	}
	driver.send(map[string]bool{"continue": true})
	release := next("released")
	if release.Receipt.State != "released" || release.Receipt.Revision != 2 || release.Receipt.RuleID != restriction.Receipt.RuleID || release.Receipt.Sequence <= restriction.Receipt.Sequence {
		t.Fatal("installed processing exact release receipt")
	}
	c.checkReceipt(t, ctx, release, "processing")
	c.checkReplay(t, ctx, session, release)
	t.Logf("installed processing stage=released after %s", time.Since(started).Round(time.Millisecond))
	invoke := func(name string, input any) (installedJourneyEnvelope, string) {
		t.Helper()
		out, err := c.Call(ctx, name, input)
		if err != nil {
			t.Fatal("installed processing restored read transport", name, err)
		}
		code := ""
		if out.Status == "error" {
			var failure struct {
				Code string `json:"code"`
			}
			if json.Unmarshal(out.Data, &failure) != nil || failure.Code == "" {
				t.Fatal("installed processing restored read refusal shape", name)
			}
			code = failure.Code
		}
		return out, code
	}
	out, code := invoke("get_case", map[string]string{"case_id": c.CaseID})
	var restored struct {
		Artifacts []struct {
			ArtifactID string    `json:"artifact_id"`
			ExpiresAt  time.Time `json:"expires_at"`
		} `json:"artifacts"`
	}
	if code != "" || out.Status != "ok" || json.Unmarshal(out.Data, &restored) != nil || len(restored.Artifacts) != 1 || restored.Artifacts[0].ArtifactID != c.ArtifactID || !restored.Artifacts[0].ExpiresAt.Equal(c.ExpiresAt) {
		t.Fatal("release did not restore the original artifact and access deadline", code)
	}
	read := func(name string, input, out any) {
		t.Helper()
		reply, code := invoke(name, input)
		if code != "" || reply.Status != "ok" || json.Unmarshal(reply.Data, out) != nil {
			t.Fatal("installed processing native preparation status", name, code)
		}
	}
	// The baseline transfer is already Completed. A fresh user-requested native
	// session is required; neither restriction nor release refills the old one.
	native, _ := installedNativeDownload(t, ctx, c.Transport, c.Identity, c.Origin, c.ArtifactID, "installed-processing-restored-"+c.ArtifactID, invoke, read, c.Diagnose, ".json")
	if !bytes.Equal(native, c.Native) {
		t.Fatal("released original artifact changed its native bytes")
	}
	driver.send(map[string]bool{"continue": true})
	next("complete")
	driver.once.Do(func() {
		_ = driver.in.Close()
		err, ok := installedAwait(t, "installed processing browser", driver.done, 15*time.Second)
		if !ok {
			driver.cancel()
			_, _ = installedAwait(t, "installed processing browser cancellation", driver.done, 30*time.Second)
		}
		if !ok || err != nil {
			t.Error("installed processing browser exit", err, driver.diagnostic.String())
		}
		driver.cancel()
	})
	t.Logf("installed processing stage=complete after %s: real React restrict/reload/exact release, both original-key replays unchanged, ordinary reads refused under restriction and original native bytes restored without extending access", time.Since(started).Round(time.Millisecond))
}

func (c installedProcessingRun) checkReceipt(t *testing.T, ctx context.Context, event installedProcessingEvent, lane string) {
	t.Helper()
	r := event.Receipt
	if !authorization.UUID(event.Key) || r.RequestID != event.Key || r.OperationID != event.Key || r.RootID != c.RootID || !authorization.UUID(r.Epoch) || !authorization.UUID(r.RuleID) {
		t.Fatal("installed processing receipt identity")
	}
	var scope value.ProcessingScope
	var raw []byte
	var revision, sequence int64
	var state, action, actualLane string
	var audited bool
	installedJourneyReadOnly(t, ctx, c.SQL, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT r.scope,r.revision,r.state,d.action,d.result_sequence,a.lane,a.intent_receipt IS NOT NULL AND a.outcome_receipt IS NOT NULL
  FROM processing_rule r JOIN processing_root p ON p.root_id=r.root_id
  JOIN processing_decision d ON d.root_id=r.root_id AND d.rule_id=r.id AND d.id=$3 AND d.applied_at IS NOT NULL AND d.result_revision=r.revision
  JOIN operation_audit a ON a.root_id=r.root_id AND a.id=d.id
  WHERE r.root_id=$1 AND r.id=$2 AND p.epoch=$4`, c.RootID, r.RuleID, r.OperationID, r.Epoch).Scan(&raw, &revision, &state, &action, &sequence, &actualLane, &audited)
	})
	if json.Unmarshal(raw, &scope) != nil || !scope.Valid() || scope.Kind != "artifact" || scope.Location.ArtifactID != c.ArtifactID || revision != r.Revision || state != r.State || sequence != r.Sequence || actualLane != lane || !audited || action != map[string]string{"restricted": "restrict_processing", "released": "release_processing"}[r.State] {
		t.Fatal("installed processing actual SQL effect/audit differs from public receipt")
	}
}
func (c installedProcessingRun) checkReplay(t *testing.T, ctx context.Context, b *installedBrowser, event installedProcessingEvent) {
	t.Helper()
	snapshot := func() string {
		t.Helper()
		var state string
		installedJourneyReadOnly(t, ctx, c.SQL, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT jsonb_build_object('rule',to_jsonb(r),
    'decisions',(SELECT jsonb_agg(to_jsonb(d) ORDER BY d.id) FROM processing_decision d WHERE d.root_id=r.root_id AND d.rule_id=r.id),
    'audits',(SELECT jsonb_agg(jsonb_build_array(a.id,a.lane,a.intent_receipt,a.outcome_receipt) ORDER BY a.id) FROM operation_audit a JOIN processing_decision d ON d.root_id=a.root_id AND d.id=a.id WHERE d.root_id=r.root_id AND d.rule_id=r.id),
    'charges',(SELECT jsonb_agg(jsonb_build_array(ac.lane,ac.principal_digest,ac.charged) ORDER BY ac.lane,ac.principal_digest) FROM operation_audit_account ac WHERE ac.root_id=r.root_id AND EXISTS(SELECT 1 FROM operation_audit a JOIN processing_decision d ON d.root_id=a.root_id AND d.id=a.id WHERE d.root_id=r.root_id AND d.rule_id=r.id AND a.lane=ac.lane AND a.principal_digest=ac.principal_digest)))::text
    FROM processing_rule r WHERE r.root_id=$1 AND r.id=$2`, c.RootID, event.Receipt.RuleID).Scan(&state)
		})
		return state
	}
	before := snapshot()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, b.base+browser.ProcessingChangesPath, bytes.NewReader(event.Input))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", b.base)
	request.Header.Set("X-CSRF-Token", b.csrf)
	request.Header.Set("Idempotency-Key", event.Key)
	response, err := b.client.Do(request)
	if err != nil {
		t.Fatal("installed processing original-key replay transport", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	var again installedProcessingReceipt
	if err != nil || response.StatusCode != 200 || len(raw) > 4096 || json.Unmarshal(raw, &again) != nil || again != event.Receipt {
		t.Fatal("installed processing original-key replay changed effect", response.StatusCode, err)
	}
	if snapshot() != before {
		t.Fatal("installed processing original-key replay changed retained rules, decisions, audit receipts or account spend")
	}
}

func startInstalledProcessingBrowser(t *testing.T, ctx context.Context, b *installedBrowser, address, artifactID, caseID string) *installedLiveBrowser {
	t.Helper()
	origin, err := url.Parse(b.base)
	if err != nil || b.client.Jar == nil {
		t.Fatal("installed processing browser session unavailable")
	}
	var cookies []map[string]any
	for _, cookie := range b.client.Jar.Cookies(origin) {
		cookies = append(cookies, map[string]any{"name": cookie.Name, "value": cookie.Value, "url": b.base, "httpOnly": true, "secure": true, "sameSite": "Lax"})
	}
	if len(cookies) == 0 {
		t.Fatal("installed processing browser cookie absent")
	}
	command, cancel := installedBoundedCommand(ctx, 3*time.Minute, "node", filepath.Join("..", "..", "web", "scripts", "installed-processing-browser.mjs"))
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	in, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := command.StdoutPipe()
	if err != nil {
		cancel()
		_ = in.Close()
		t.Fatal(err)
	}
	diagnostic := &consoleBoundedOutput{}
	command.Stderr = diagnostic
	p := &installedLiveBrowser{t: t, in: in, events: make(chan json.RawMessage, 8), done: make(chan error, 1), cancel: cancel, cmd: command, diagnostic: diagnostic}
	if err = command.Start(); err != nil {
		cancel()
		_ = in.Close()
		t.Fatal(err)
	}
	go func() {
		scanner := bufio.NewScanner(out)
		scanner.Buffer(make([]byte, 1024), 32<<10)
		for scanner.Scan() {
			line := append(json.RawMessage(nil), scanner.Bytes()...)
			select {
			case p.events <- line:
			case <-ctx.Done():
			}
		}
		close(p.events)
		err := command.Wait()
		if err == nil {
			err = scanner.Err()
		}
		p.done <- err
	}()
	t.Cleanup(func() {
		p.once.Do(func() {
			p.cancel()
			_ = p.in.Close()
			installedAwait(t, "installed processing browser", p.done, 30*time.Second)
		})
	})
	p.send(map[string]any{"origin": b.base, "proxy": installedHistoryBrowserTunnel(t, ctx, b.base, address), "cookies": cookies, "artifactID": artifactID, "casePath": "/cases/" + caseID})
	clear(cookies)
	return p
}
