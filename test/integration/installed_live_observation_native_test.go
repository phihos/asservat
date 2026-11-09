package integration

// Installed qualification uses only the real public/session/source pipelines.
// Administrator SQL is read-only evidence, never an authority producer.
import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type installedLiveRun struct {
	SQL *pgxpool.Pool
	API kubernetes.Interface
	// Administrator is the installer's configured administrator account,
	// the only actor the guarded delivery ConfigMap accepts updates from.
	Administrator                                                   kubernetes.Interface
	AdministratorUser                                               string
	RootID, Installation, HubNamespace, OwnerDeployment             string
	Failover                                                        bool
	Fanout                                                          bool
	BeforeFailover                                                  func()
	Identity                                                        *installedIdentity
	PublicRoot                                                      []byte
	Address, Origin, RegionalConfig, ClusterID, Namespace, Workload string
	Diagnose                                                        func()
}

type installedLiveReply struct {
	installedJourneyEnvelope
	NextCursor *string `json:"next_cursor"`
}

// First enablement changes the existing protected administrator document only.
// It cannot add a placement, download client, source or observation permit.
func installedLiveSettings(in contracts.DownloadEnvironmentSettings, root, cluster, issuer string) (contracts.DownloadEnvironmentSettings, error) {
	var out contracts.DownloadEnvironmentSettings
	if in.Format != contracts.DownloadEnvironmentFormat || in.RootID != root || in.Revision < 1 || in.Revision >= 2147483647 || in.LiveRead != nil {
		return out, errors.New("original disabled delivery settings required")
	}
	raw, err := json.Marshal(in)
	if err != nil || json.Unmarshal(raw, &out) != nil {
		return out, errors.New("delivery settings encoding")
	}
	var paths []string
	for _, p := range in.Paths {
		if p.TargetClusterID == cluster {
			paths = append(paths, p.ID)
		}
	}
	if len(paths) != 1 {
		return out, errors.New("one existing installed path required")
	}
	clients := make([]contracts.LiveReadClient, 0, 2)
	for _, id := range []string{"console", "mcp"} {
		matches := 0
		for _, c := range in.Clients {
			if c.ID == id && c.Issuer == issuer && c.Kind == "human" && slices.Contains(c.PathIDs, paths[0]) {
				matches++
				clients = append(clients, contracts.LiveReadClient{Issuer: c.Issuer, ID: c.ID, Kind: c.Kind, PathIDs: slices.Clone(paths)})
			}
		}
		if matches != 1 {
			return out, errors.New("existing exact console and MCP clients required")
		}
	}
	out.Revision++
	out.LiveRead = &contracts.LiveReadSettings{Root: contracts.LiveRootSettings{Watches: 4, PrincipalWatches: 2, WorkloadWatches: 2, Rate: 1 << 20, Burst: 1 << 20}, Projections: []string{v.Packet, v.Syscall, v.HTTP}, Clients: clients, Ceilings: []contracts.LiveReadCeiling{{ClusterID: cluster, Duration: 120, Output: 1 << 20, Rate: 64 << 10, Rows: 20, Buffer: 128 << 10, RowAge: 30, Replay: 5}}}
	encoded, err := json.Marshal(out)
	if err != nil || len(encoded) > contracts.DownloadEnvironmentMaxBytes {
		return contracts.DownloadEnvironmentSettings{}, errors.New("delivery settings bound")
	}
	return out, nil
}

func installedLiveOwnerEpoch(ctx context.Context, db *pgxpool.Pool, installation, podUID string) (string, error) {
	rows, err := db.Query(ctx, `SELECT e.process_epoch::text FROM hub_owner_enrollment e JOIN hub_owner_certificate c ON c.enrollment_id=e.id JOIN fleet_current_trust t ON t.installation_id=e.installation_id AND t.issuer_epoch=e.issuer_epoch WHERE e.installation_id=$1 AND e.pod_uid=$2 AND e.usage='server' AND e.retired_at IS NULL AND e.audit_receipt_json IS NOT NULL AND c.activated_at IS NOT NULL AND c.audit_receipt_json IS NOT NULL AND c.not_after>clock_timestamp() AND NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until ORDER BY c.activated_at DESC LIMIT 1`, installation, podUID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var epochs []string
	for rows.Next() {
		var e string
		if rows.Scan(&e) != nil {
			return "", errors.New("owner registration shape")
		}
		epochs = append(epochs, e)
	}
	// A container restart leaves the earlier process's unexpired
	// registration; the most recently activated one is the current process.
	if rows.Err() != nil || len(epochs) != 1 {
		return "", errors.New("current activated server epoch required")
	}
	return epochs[0], nil
}
func installedLiveReadyPod(ctx context.Context, api kubernetes.Interface, namespace, selector string) (core.Pod, error) {
	list, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: selector, Limit: 3})
	if err != nil || len(list.Items) != 1 {
		return core.Pod{}, errors.New("one original owner Pod required")
	}
	p := list.Items[0]
	// An earlier container restart during installation is normal; the
	// current activated server epoch below identifies the process.
	if p.DeletionTimestamp != nil {
		return core.Pod{}, errors.New("owner Pod deleting")
	}
	for _, c := range p.Status.Conditions {
		if c.Type == core.PodReady && c.Status == core.ConditionTrue {
			return p, nil
		}
	}
	return core.Pod{}, errors.New("owner Pod not Ready")
}
func installedLiveEnable(t *testing.T, ctx context.Context, c installedLiveRun) {
	t.Helper()
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	deployment, err := c.API.AppsV1().Deployments(c.HubNamespace).Get(call, c.OwnerDeployment, meta.GetOptions{})
	if err != nil {
		t.Fatal("original owner Deployment", err)
	}
	selector := meta.FormatLabelSelector(deployment.Spec.Selector)
	before, err := installedLiveReadyPod(call, c.API, c.HubNamespace, selector)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := installedLiveOwnerEpoch(call, c.SQL, c.Installation, string(before.UID))
	if err != nil {
		t.Fatal("original activated owner", err)
	}
	name := contracts.OwnerDownloadEnvironmentName(c.Installation)
	// Fixture-only RBAC for the configured administrator: get/update of this
	// one ConfigMap. The admission guard independently requires the actor.
	if err := installedLiveAdministratorRBAC(call, c.API, name, before.Name, c.AdministratorUser); err != nil {
		t.Fatal("fixture administrator RBAC", err)
	}
	cm, err := c.API.CoreV1().ConfigMaps(c.HubNamespace).Get(call, name, meta.GetOptions{})
	if err != nil || cm.UID == "" || cm.ResourceVersion == "" || len(cm.Data) != 1 {
		t.Fatal("original guarded delivery source", err)
	}
	var current contracts.DownloadEnvironmentSettings
	if json.Unmarshal([]byte(cm.Data[contracts.DownloadEnvironmentFile]), &current) != nil {
		t.Fatal("guarded delivery source shape")
	}
	settings, err := installedLiveSettings(current, c.RootID, c.ClusterID, c.Identity.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	next := cm.DeepCopy()
	next.Data[contracts.DownloadEnvironmentFile] = string(raw)
	changed, err := c.Administrator.CoreV1().ConfigMaps(c.HubNamespace).Update(call, next, meta.UpdateOptions{FieldValidation: "Strict"})
	if err != nil || changed.UID != cm.UID || changed.ResourceVersion == cm.ResourceVersion {
		t.Fatal("installation administrator delivery CAS", err)
	}
	uid := before.UID
	if err = c.Administrator.CoreV1().Pods(c.HubNamespace).Delete(call, before.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid}}); err != nil {
		t.Fatal("installation administrator exact old owner deletion", err)
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		p, e := installedLiveReadyPod(call, c.API, c.HubNamespace, selector)
		if e == nil && p.UID != before.UID {
			newEpoch, e := installedLiveOwnerEpoch(call, c.SQL, c.Installation, string(p.UID))
			if e == nil && newEpoch != epoch {
				nowDeployment, e := c.API.AppsV1().Deployments(c.HubNamespace).Get(call, c.OwnerDeployment, meta.GetOptions{})
				if e != nil || nowDeployment.UID != deployment.UID || nowDeployment.Generation != deployment.Generation {
					t.Fatal("administrator restart changed accepted Deployment")
				}
				if len(p.OwnerReferences) != 1 || len(before.OwnerReferences) != 1 || p.OwnerReferences[0].UID != before.OwnerReferences[0].UID {
					t.Fatal("restart replaced original ReplicaSet")
				}
				t.Logf("guarded delivery revision%d accepted; exact oldPod%s replacedby%s with distinct currentactivated server epoch; original Deployment/ReplicaSet retained", settings.Revision, before.UID, p.UID)
				return
			}
		}
		select {
		case <-call.Done():
			c.Diagnose()
			t.Fatal("new owner enrollment/Ready proof unavailable", call.Err())
		case <-ticker.C:
		}
	}
}

func qualifyInstalledLiveObservation(t *testing.T, ctx context.Context, c installedLiveRun) {
	t.Helper()
	if _, err := os.Stat("/etc/asservat-disposable-host"); err != nil {
		t.Fatal("installed live requires disposable runner")
	}
	defer func() {
		if t.Failed() && c.Diagnose != nil {
			c.Diagnose()
		}
	}()
	installedLiveEnable(t, ctx, c)
	cert, err := x509.ParseCertificate(c.PublicRoot)
	if err != nil {
		t.Fatal(err)
	}
	c.Identity.initializeProcessing(t, ctx, cert, c.Address, c.Origin, c.Diagnose)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	dial := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DialContext: func(call context.Context, network, _ string) (net.Conn, error) {
		return dial.DialContext(call, network, c.Address)
	}}
	defer transport.CloseIdleConnections()
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-live-observation", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(c.Origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, c.Identity.mcpTokenSource(c.Origin).Token}, Timeout: 45 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	liveCalls := 0
	call := func(parent context.Context, name string, input any) (installedLiveReply, string, error) {
		var zero installedLiveReply
		raw, e := json.Marshal(input)
		if e != nil || wire.ValidateInput(name, raw) != nil {
			return zero, "", errors.New("invalid authored installed input")
		}
		// The service bounds each phase at five seconds itself.
		bounded, stop := context.WithTimeout(parent, 25*time.Second)
		defer stop()
		reply, e := session.CallTool(bounded, &sdk.CallToolParams{Name: name, Arguments: input})
		if e != nil {
			return zero, "", e
		}
		envelope, code, e := installedJourneyReplyCode(wire, name, reply)
		if e != nil {
			return zero, "", e
		}
		raw, e = json.Marshal(reply.StructuredContent)
		if e != nil || json.Unmarshal(raw, &zero) != nil {
			return zero, "", errors.New("installed live result shape")
		}
		zero.installedJourneyEnvelope = envelope
		if strings.HasSuffix(name, "live_watch") || name == "list_live_sources" {
			liveCalls++
			if liveCalls > 100 {
				return zero, "", errors.New("bounded live operation count exceeded")
			}
		}
		return zero, code, nil
	}
	invoke := installedRecordingInvoke(func(callCtx context.Context, name string, input any) (installedJourneyEnvelope, string, error) {
		r, code, e := call(callCtx, name, input)
		return r.installedJourneyEnvelope, code, e
	})
	console := c.Identity.consoleSession(t, ctx, cert, c.Address, c.Origin)
	browser := startInstalledLiveBrowser(t, ctx, console, c.Address, map[string]string{"cluster_id": c.ClusterID, "namespace": c.Namespace, "kind": "Deployment", "name": c.Workload})
	defer browser.close()
	episodes := 0
	qualifyInstalledLiveSources(t, ctx, c.SQL, c.Identity, c.PublicRoot, c.Address, c.Origin, c.RegionalConfig, c.RootID, transport, invoke, func(callCtx context.Context, source installedLiveFixture) error {
		episodes++
		if episodes > 6 {
			return errors.New("more than six original source episodes")
		}
		if source.SourceID == "" || source.PodUID == "" || source.ActionID == "" || !source.HardUntil.IsZero() && !time.Now().Before(source.HardUntil) {
			return errors.New("actual original running source required")
		}
		if source.Kind == "manualSession" {
			// A finite session ends within its window: observe it from React
			// and MCP at the same time instead of one after the other.
			browser.begin(source)
			c.Failover = episodes == 1 && os.Getenv("ASSERVAT_LIVE_EPISODES") == "policy"
			c.Fanout = episodes == 1
			c.BeforeFailover = func() { browser.finishEpisode(source) }
			if e := installedLiveMCP(t, callCtx, c.SQL, c.RootID, source, call, c); e != nil {
				return e
			}
			if !c.Failover && !c.Fanout {
				browser.finishEpisode(source)
			}
			return nil
		}
		// The fanout episode holds React open while MCP exercises the shared ceiling.
		c.Failover = episodes == 1 && os.Getenv("ASSERVAT_LIVE_EPISODES") == "policy"
		c.Fanout = episodes == 1
		if c.Fanout {
			browser.begin(source)
			c.BeforeFailover = func() { browser.finishEpisode(source) }
		}
		if e := installedLiveMCP(t, callCtx, c.SQL, c.RootID, source, call, c); e != nil {
			return e
		}
		if !c.Fanout {
			browser.begin(source)
			browser.finishEpisode(source)
		}
		return nil
	})
	want := 6
	if m := os.Getenv("ASSERVAT_LIVE_EPISODES"); m == "manual" || m == "policy" {
		want = 3
	}
	if episodes != want {
		t.Fatal("incomplete installed projection/source matrix", episodes)
	}
	browser.close()
	t.Logf("installed live: six original source episodes, realC3/SQL/owner/node and React+officialSDK; MCP%d live operations, no viewer acquisition", liveCalls)
}

type installedLiveCall func(context.Context, string, any) (installedLiveReply, string, error)

func installedLiveRestartOwner(t *testing.T, ctx context.Context, c installedLiveRun) {
	t.Helper()
	call, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	deployment, err := c.API.AppsV1().Deployments(c.HubNamespace).Get(call, c.OwnerDeployment, meta.GetOptions{})
	if err != nil {
		t.Fatal("live failover owner Deployment", err)
	}
	selector := meta.FormatLabelSelector(deployment.Spec.Selector)
	before, err := installedLiveReadyPod(call, c.API, c.HubNamespace, selector)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := installedLiveOwnerEpoch(call, c.SQL, c.Installation, string(before.UID))
	if err != nil {
		t.Fatal("live failover original activated owner", err)
	}
	uid := before.UID
	if err = c.Administrator.CoreV1().Pods(c.HubNamespace).Delete(call, before.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid}}); err != nil {
		t.Fatal("live failover exact old owner deletion", err)
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		p, e := installedLiveReadyPod(call, c.API, c.HubNamespace, selector)
		if e == nil && p.UID != before.UID {
			newEpoch, e := installedLiveOwnerEpoch(call, c.SQL, c.Installation, string(p.UID))
			if e == nil && newEpoch != epoch {
				nowDeployment, e := c.API.AppsV1().Deployments(c.HubNamespace).Get(call, c.OwnerDeployment, meta.GetOptions{})
				if e != nil || nowDeployment.UID != deployment.UID || nowDeployment.Generation != deployment.Generation {
					t.Fatal("live failover changed accepted Deployment")
				}
				if len(p.OwnerReferences) != 1 || len(before.OwnerReferences) != 1 || p.OwnerReferences[0].UID != before.OwnerReferences[0].UID {
					t.Fatal("live failover replaced original ReplicaSet")
				}
				t.Logf("live failover: exact oldPod%s replacedby%s with distinct currentactivated server epoch; original Deployment/ReplicaSet retained", before.UID, p.UID)
				return
			}
		}
		select {
		case <-call.Done():
			c.Diagnose()
			t.Fatal("live failover owner enrollment/Ready proof unavailable", call.Err())
		case <-ticker.C:
		}
	}
}

func installedLiveMCP(t *testing.T, ctx context.Context, db *pgxpool.Pool, root string, source installedLiveFixture, call installedLiveCall, run installedLiveRun) error {
	t.Helper()
	must := func(name string, args any, out any) (installedLiveReply, error) {
		r, code, e := call(ctx, name, args)
		// A retryable refusal (for example a source lease renewing) failed only
		// that call; retry it a bounded number of times and record each one.
		for attempt := 1; e == nil && code == "LiveUnavailable" && attempt <= 5; attempt++ {
			var failure struct {
				Retryable bool `json:"retryable"`
			}
			if json.Unmarshal(r.Data, &failure) != nil || !failure.Retryable {
				break
			}
			t.Logf("installed live %s attempt %d retryable LiveUnavailable; retrying", name, attempt)
			if e = installedJourneyPause(ctx, time.Second); e != nil {
				return r, e
			}
			r, code, e = call(ctx, name, args)
		}
		if e != nil || code != "" || r.Status != "ok" {
			return r, fmt.Errorf("installed live %s: %s %w", name, code, e)
		}
		if out != nil && json.Unmarshal(r.Data, out) != nil {
			return r, errors.New("installed live typed result")
		}
		return r, nil
	}
	// A just-armed source may still be warming; wait a bounded time for the
	// same original source to become eligible, never for a replacement.
	var page v.SourcePage
	var selected *v.SourceRow
	for attempt := 0; ; attempt++ {
		r, code, e := call(ctx, "list_live_sources", map[string]any{"target_ref": source.Target, "limit": 20})
		if e == nil && code == "LiveUnavailable" && attempt < 30 {
			// Read-only inventory; record transient refusals instead of hiding them.
			t.Logf("installed live inventory attempt %d refused LiveUnavailable; retrying", attempt)
			if e := installedJourneyPause(ctx, 2*time.Second); e != nil {
				return e
			}
			continue
		}
		if e != nil || code != "" || r.Status != "ok" || json.Unmarshal(r.Data, &page) != nil {
			return fmt.Errorf("installed live list_live_sources: %s %v", code, e)
		}
		selected = nil
		for n := range page.Sources {
			if s := &page.Sources[n]; s.ID == source.SourceID {
				selected = s
			}
		}
		if selected != nil && selected.Eligible || attempt == 30 {
			break
		}
		if selected != nil {
			t.Logf("installed live source %s attempt %d state=%s blockers=%v; waiting", selected.ID, attempt, selected.State, selected.Blockers)
		}
		if e := installedJourneyPause(ctx, 2*time.Second); e != nil {
			return e
		}
	}
	if selected == nil || !selected.Eligible || selected.PodUID != source.PodUID || selected.ActionID != source.ActionID || selected.OwnerKind != source.Kind || !slices.Contains(selected.Projections, source.Projection) {
		for _, r := range page.Sources {
			t.Logf("listed live source %s kind=%s action=%s pod=%s state=%s eligible=%v blockers=%v projections=%v", r.ID, r.OwnerKind, r.ActionID, r.PodUID, r.State, r.Eligible, r.Blockers, r.Projections)
		}
		t.Logf("expected live source %s kind=%s action=%s pod=%s projection=%s", source.SourceID, source.Kind, source.ActionID, source.PodUID, source.Projection)
		return errors.New("inventory substituted original source")
	}
	var watch v.Watch
	request := map[string]any{"source_handles": []string{selected.Handle}, "projection": source.Projection, "idempotency_key": "live-installed-" + source.SourceID, "duration_seconds": 90, "max_output_bytes": 256 << 10}
	if _, e := must("open_live_watch", request, &watch); e != nil {
		return e
	}
	if !slices.Equal(watch.SourceIDs, []string{source.SourceID}) || watch.Cursor == nil || !source.HardUntil.IsZero() && watch.ExpiresAt.After(source.HardUntil) {
		return errors.New("watch extended or replaced original source")
	}
	before := watch
	var priorSpent int64
	if e := db.QueryRow(ctx, `SELECT spent FROM live_watch_control WHERE root_id=$1 AND id=$2`, root, watch.ID).Scan(&priorSpent); e != nil {
		return e
	}
	readInput := map[string]any{"watch_id": watch.ID, "cursor": *watch.Cursor, "limit": 20, "wait_ms": 1000}
	var received installedLiveReply
	var receivedAt time.Time
	var batch *v.Batch
	for tries := 0; tries < 4; tries++ {
		r, e := must("read_live_watch", readInput, nil)
		if e != nil {
			return e
		}
		wrapped, _ := json.Marshal(map[string]any{"batch": r.Data})
		decoded, e := liveapp.DecodeOwnerResult(wrapped, time.Now())
		if e != nil || decoded.Batch == nil {
			return errors.New("closed approved row union invalid")
		}
		received, receivedAt = r, time.Now()
		batch = decoded.Batch
		if len(batch.Rows) > 0 {
			break
		}
		if r.NextCursor == nil {
			return errors.New("quiet source lost continuation")
		}
		readInput["cursor"] = *r.NextCursor
	}
	if batch == nil || len(batch.Rows) == 0 {
		return errors.New("real source has no qualified approved live row")
	}
	for _, r := range batch.Rows {
		if r.SourceID != source.SourceID || r.PodUID != source.PodUID || r.Projection != source.Projection || !source.HardUntil.IsZero() && r.ExpiresAt.After(source.HardUntil) || !r.Valid(time.Now()) {
			return errors.New("row source/time/projection changed")
		}
		raw, _ := json.Marshal(r)
		if bytesHaveLiveCanary(raw) {
			return errors.New("source canary entered approved projection")
		}
	}
	// Replay is retained only until the earliest row expiry and the replay
	// ceiling, both from delivery; assert equality only inside that window.
	replayUntil := receivedAt.Add(5 * time.Second)
	for _, r := range batch.Rows {
		replayUntil = identity.Earlier(replayUntil, r.ExpiresAt)
	}
	replay, e := must("read_live_watch", readInput, nil)
	if e != nil {
		return e
	}
	var a, b map[string]json.RawMessage
	if json.Unmarshal(received.Data, &a) != nil || json.Unmarshal(replay.Data, &b) != nil {
		return errors.New("replay shape")
	}
	if replayedAt := time.Now(); !replayedAt.Before(replayUntil) {
		t.Logf("installed live replay after its retained window (%s late); equality not asserted", replayedAt.Sub(replayUntil).Round(time.Millisecond))
	} else if string(a["batch_id"]) != string(b["batch_id"]) || string(a["rows"]) != string(b["rows"]) {
		t.Logf("replay mismatch: received batch %s rows %d, replay batch %s, window left %s", a["batch_id"], len(batch.Rows), b["batch_id"], time.Until(replayUntil).Round(time.Millisecond))
		return errors.New("same cursor changed retained observations")
	}
	var firstSpend, lastSpend int64
	_ = json.Unmarshal(a["output_bytes_spent"], &firstSpend)
	_ = json.Unmarshal(b["output_bytes_spent"], &lastSpend)
	if firstSpend <= priorSpent || lastSpend <= firstSpend {
		return errors.New("same cursor delivery did not retain charge")
	}
	// No returned row, cursor or HTTP preview is accepted as SQL accounting proof.
	var sqlSpent int64
	var state string
	if e = db.QueryRow(ctx, `SELECT spent,state FROM live_watch_control WHERE root_id=$1 AND id=$2`, root, watch.ID).Scan(&sqlSpent, &state); e != nil || sqlSpent != lastSpend || state != "Active" {
		return errors.New("public accounting differs from actual minimized ledger")
	}
	if run.Fanout {
		var active int
		if e = db.QueryRow(ctx, `SELECT count(*) FROM live_watch_control WHERE root_id=$1 AND state IN ('Active','Paused','Disconnected')`, root).Scan(&active); e != nil || active != 2 {
			return errors.New("principal ceiling fixture did not retain React and MCP views")
		}
		thirdInput := make(map[string]any, len(request))
		for key, value := range request {
			thirdInput[key] = value
		}
		thirdInput["idempotency_key"] = "live-ceiling-third-" + source.SourceID
		refusal, code, e := call(ctx, "open_live_watch", thirdInput)
		var failure struct {
			Retryable bool `json:"retryable"`
		}
		if e != nil || code != "CapacityUnavailable" || refusal.Status != "error" || json.Unmarshal(refusal.Data, &failure) != nil || failure.Retryable {
			return fmt.Errorf("third concurrent view was not refused by the principal ceiling: %s %w", code, e)
		}
		if e = db.QueryRow(ctx, `SELECT count(*) FROM live_watch_control WHERE root_id=$1 AND state IN ('Active','Paused','Disconnected')`, root).Scan(&active); e != nil || active != 2 {
			return errors.New("principal ceiling refusal changed the original views")
		}
		if run.BeforeFailover != nil {
			run.BeforeFailover()
		}
		t.Log("installed live principal ceiling: third concurrent view refused CapacityUnavailable; React and MCP views retained")
	}
	closeInput := map[string]any{"watch_id": watch.ID, "expected_revision": watch.Revision, "idempotency_key": "live-close-" + source.SourceID}
	if run.Failover {
		installedLiveRestartOwner(t, ctx, run)
		var recovered v.Batch
		var r installedLiveReply
		for attempt := 0; attempt < 12; attempt++ {
			r, e = must("read_live_watch", readInput, nil)
			if e == nil {
				if json.Unmarshal(r.Data, &recovered) != nil {
					return errors.New("live failover response shape")
				}
				if recovered.State == "Closed" || recovered.State == "Active" && len(recovered.Gaps) != 0 {
					break
				}
			} else if !strings.Contains(e.Error(), "LiveUnavailable") {
				return e
			}
			if attempt == 11 {
				return errors.New("live failover produced no explicit gap or closed state")
			}
			if e = installedJourneyPause(ctx, time.Second); e != nil {
				return e
			}
		}
		if recovered.WatchID != watch.ID || recovered.Revision != watch.Revision || len(recovered.Rows) != 0 {
			return errors.New("live failover changed the view or replayed retained rows")
		}
		if recovered.State == "Closed" {
			if r.NextCursor != nil {
				return errors.New("live failover closed view retained continuation")
			}
			if e = db.QueryRow(ctx, `SELECT spent,state FROM live_watch_control WHERE root_id=$1 AND id=$2`, root, watch.ID).Scan(&sqlSpent, &state); e != nil || sqlSpent != lastSpend || state != "Closed" {
				return errors.New("live failover terminal reply differs from minimized ledger")
			}
			return nil
		}
		if r.NextCursor == nil {
			return errors.New("live failover lost continuation without closing the view")
		}
		closeInput["expected_revision"] = recovered.Revision
		if _, e = must("close_live_watch", closeInput, &watch); e != nil {
			return e
		}
		closed := watch
		if _, e = must("close_live_watch", closeInput, &watch); e != nil || watch.ID != closed.ID || watch.Revision != closed.Revision || watch.State != "Closed" || !watch.ExpiresAt.Equal(before.ExpiresAt) {
			return errors.New("live failover Close replay changed the original view")
		}
		return nil
	}
	for n, mode := range []string{"Paused", "Active"} {
		if _, e = must("update_live_watch", map[string]any{"watch_id": watch.ID, "expected_revision": watch.Revision, "idempotency_key": fmt.Sprintf("live-change-%s-%d", source.SourceID, n), "mode": mode}, &watch); e != nil {
			return e
		}
		if watch.ExpiresAt != before.ExpiresAt {
			return errors.New("view change renewed original end")
		}
	}
	closeInput["expected_revision"] = watch.Revision
	if _, e = must("close_live_watch", closeInput, &watch); e != nil {
		return e
	}
	closed := watch
	if _, e = must("close_live_watch", closeInput, &watch); e != nil || watch.ID != closed.ID || watch.Revision != closed.Revision || watch.State != "Closed" || !watch.ExpiresAt.Equal(before.ExpiresAt) {
		return errors.New("original Close receipt replay changed")
	}
	return nil
}
func bytesHaveLiveCanary(raw []byte) bool {
	return strings.Contains(string(raw), manualHTTPMarker) || strings.Contains(string(raw), installedLiveProducerMarker)
}

// Persistent driver is ready before a short finite HTTP source starts. Private
// stdin contains only original test cookies and expected source metadata.
type installedLiveBrowser struct {
	t          *testing.T
	in         io.WriteCloser
	events     chan json.RawMessage
	done       chan error
	cancel     context.CancelFunc
	cmd        *exec.Cmd
	diagnostic *consoleBoundedOutput
	once       sync.Once
}

func startInstalledLiveBrowser(t *testing.T, ctx context.Context, b *installedBrowser, address string, target map[string]string) *installedLiveBrowser {
	t.Helper()
	u, e := url.Parse(b.base)
	if e != nil || b.client.Jar == nil {
		t.Fatal("actual installed browser session missing")
	}
	var cookies []map[string]any
	for _, c := range b.client.Jar.Cookies(u) {
		cookies = append(cookies, map[string]any{"name": c.Name, "value": c.Value, "url": b.base, "httpOnly": true, "secure": true, "sameSite": "Lax"})
	}
	if len(cookies) == 0 {
		t.Fatal("actual browser cookie absent")
	}
	call, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(call, "node", filepath.Join("..", "..", "web", "scripts", "installed-live-observation-browser.mjs"))
	// Chromium children keep stdout open after node is killed; bound Wait.
	cmd.WaitDelay = 5 * time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	in, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	diag := &consoleBoundedOutput{}
	cmd.Stderr = diag
	p := &installedLiveBrowser{t: t, in: in, events: make(chan json.RawMessage, 8), done: make(chan error, 1), cancel: cancel, cmd: cmd, diagnostic: diag}
	if e = cmd.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	go func() {
		s := bufio.NewScanner(out)
		s.Buffer(make([]byte, 1024), 32<<10)
		for s.Scan() {
			raw := append(json.RawMessage(nil), s.Bytes()...)
			select {
			case p.events <- raw:
			case <-call.Done():
				break
			}
		}
		close(p.events)
		p.done <- cmd.Wait()
	}()
	// Cancel kills the process group; WaitDelay then closes held pipes, so the
	// join normally ends within seconds. The bound reports a stuck reader.
	t.Cleanup(func() {
		p.cancel()
		_ = p.in.Close()
		p.once.Do(func() { installedAwait(t, "installed live browser", p.done, 30*time.Second) })
	})
	p.send(map[string]any{"mode": "installed-live", "origin": b.base, "proxy": installedHistoryBrowserTunnel(t, ctx, b.base, address), "cookies": cookies, "target": target})
	clear(cookies)
	var ready struct {
		Kind string `json:"kind"`
	}
	p.read(&ready)
	if ready.Kind != "ready" {
		t.Fatal("installed browser not ready")
	}
	return p
}
func (p *installedLiveBrowser) send(v any) {
	p.t.Helper()
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 16<<10 {
		p.t.Fatal("bounded installed browser command")
	}
	if _, e = p.in.Write(append(raw, '\n')); e != nil {
		p.t.Fatal("browser input unavailable")
	}
	clear(raw)
}
func (p *installedLiveBrowser) read(out any) {
	p.t.Helper()
	var raw json.RawMessage
	ok := false
	select {
	case raw, ok = <-p.events:
	case <-time.After(3 * time.Minute):
		// A stuck browser script must not hold the test until the CI job limit.
	}
	if !ok || json.Unmarshal(raw, out) != nil {
		p.t.Fatal("installed browser event unavailable", p.diagnostic.String())
	}
}
func (p *installedLiveBrowser) begin(s installedLiveFixture) {
	p.send(map[string]any{"kind": "observe", "source": map[string]any{"source_id": s.SourceID, "action_id": s.ActionID, "pod_uid": s.PodUID, "kind": s.Kind, "projection": s.Projection, "hard_until": installedLiveHardUntil(s.HardUntil), "forbidden": []string{manualHTTPMarker, installedLiveProducerMarker}}})
	var opened struct {
		Kind       string `json:"kind"`
		Source     string `json:"source_id"`
		Projection string `json:"projection"`
		WatchID    string `json:"watch_id"`
	}
	p.read(&opened)
	if opened.Kind != "opened" || opened.Source != s.SourceID || opened.Projection != s.Projection || opened.WatchID == "" {
		p.t.Fatal("actual React open proof failed", opened, p.diagnostic.String())
	}
}
func (p *installedLiveBrowser) finishEpisode(s installedLiveFixture) {
	p.t.Helper()
	p.send(map[string]any{"kind": "release"})
	var e struct {
		Kind, SourceID, Projection, WatchID string
		Rows, Clear                         bool
		Source                              string `json:"source_id"`
		Rendered                            bool   `json:"rows_rendered"`
		Cleared                             bool   `json:"cleared"`
	}
	p.read(&e)
	if e.Kind != "observed" || e.Source != s.SourceID || e.Projection != s.Projection || !e.Rendered || !e.Cleared {
		p.t.Fatal("actual React source/render/clear proof failed")
	}
}
func (p *installedLiveBrowser) close() {
	p.once.Do(func() {
		if p.t.Failed() {
			// No finish handshake after a failure: the script may be stuck.
			p.cancel()
			installedAwait(p.t, "installed live browser", p.done, 30*time.Second)
			return
		}
		p.send(map[string]any{"kind": "finish"})
		var e struct {
			Kind string `json:"kind"`
		}
		p.read(&e)
		if e.Kind != "done" {
			p.t.Error("installed browser did not complete")
		}
		_ = p.in.Close()
		// The script reported done; its browser process may linger after
		// stdin closes, so bound the exit wait and then stop it.
		select {
		case err := <-p.done:
			if err != nil {
				p.t.Error("installed browser failed", p.diagnostic.String())
			}
			p.cancel()
		case <-time.After(15 * time.Second):
			p.cancel()
			installedAwait(p.t, "installed live browser", p.done, 30*time.Second)
		}
	})
}

// Digest is minimized fixture evidence only, not source or read authority.
func installedLiveDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func installedLiveAdministratorRBAC(ctx context.Context, api kubernetes.Interface, configMap, pod, user string) error {
	// Cluster-scoped, because the hub namespace guard admits no other writer.
	// Rules name only the exact ConfigMap and the exact old owner Pod.
	name := "installed-live-delivery-administrator"
	if _, err := api.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{configMap}, Verbs: []string{"get", "update"}}, {APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{pod}, Verbs: []string{"delete"}}}}, meta.CreateOptions{}); err != nil {
		return err
	}
	_, err := api.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, RoleRef: rbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: name}, Subjects: []rbac.Subject{{Kind: "User", Name: user}}}, meta.CreateOptions{})
	return err
}

var (
	installedLiveGuardUser  = regexp.MustCompile(`^request\.userInfo\.username == "([^"]+)"$`)
	installedLiveGuardGroup = regexp.MustCompile(`^"([^"]+)" in request\.userInfo\.groups$`)
)

// installedLiveAdministrator reads the plain administrator clauses of both
// current guards and returns one identity that both accept.
func installedLiveAdministrator(ctx context.Context, api kubernetes.Interface, workloadGuard, deliveryGuard string) (string, []string, error) {
	actors := func(name string) (users, groups []string, err error) {
		p, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, name, meta.GetOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, v := range p.Spec.Validations {
			for _, clause := range strings.Split(v.Expression, " || ") {
				clause = strings.Trim(strings.TrimSpace(clause), "()")
				if m := installedLiveGuardUser.FindStringSubmatch(clause); m != nil {
					users = append(users, m[1])
				} else if m := installedLiveGuardGroup.FindStringSubmatch(clause); m != nil {
					groups = append(groups, m[1])
				}
			}
		}
		return users, groups, nil
	}
	wu, wg, err := actors(workloadGuard)
	if err != nil {
		return "", nil, err
	}
	du, dg, err := actors(deliveryGuard)
	if err != nil {
		return "", nil, err
	}
	for _, u := range wu {
		if slices.Contains(du, u) {
			return u, nil, nil
		}
	}
	switch {
	case len(du) > 0 && len(wg) > 0:
		return du[0], wg, nil
	case len(wu) > 0 && len(dg) > 0:
		return wu[0], dg, nil
	case len(wg) > 0 && len(dg) > 0:
		return "installed-live-administrator", append(wg, dg...), nil
	}
	return "", nil, fmt.Errorf("no administrator accepted by both guards: workload users %v groups %v, delivery users %v groups %v", wu, wg, du, dg)
}

// installedLiveHardUntil is null for a manual session, whose lease comes from
// the live catalog rather than a known policy source hard end.
func installedLiveHardUntil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
