package integration

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/privacy"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type reportPageSummary struct {
	Query         value.ProcessingReportQuery `json:"query"`
	RequestID     string                      `json:"requestID"`
	ResponseBytes int64                       `json:"responseBytes"`
}
type reportExportEvent struct {
	Kind     string              `json:"kind"`
	File     string              `json:"file"`
	Part     int                 `json:"part"`
	Complete bool                `json:"complete"`
	Bytes    int64               `json:"bytes"`
	SHA256   string              `json:"sha256"`
	Pages    []reportPageSummary `json:"pages"`
	Stage    string              `json:"stage"`
	Reason   string              `json:"reason"`
	Check    string              `json:"check"`
}
type processingReportExport struct {
	Format   string                       `json:"format"`
	Part     int                          `json:"part"`
	Pages    []installedJourneyEnvelope   `json:"pages"`
	Next     *value.ProcessingReportQuery `json:"next,omitempty"`
	Complete bool                         `json:"complete"`
}

func TestInstalledReportSharingAuthority(t *testing.T) {
	for _, fixture := range []struct {
		foci  string
		owner bool
	}{
		{"privacy-inventory", true}, {"share", true}, {"browser", true}, {"share-retirement", true},
		{"early-erasure", false}, {"early-erasure,privacy-inventory", true},
	} {
		t.Run(fixture.foci, func(t *testing.T) {
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", fixture.foci)
			owner := false
			for _, role := range installedRegionalBindingRoles() {
				owner = owner || role == "evidence-owner"
			}
			if owner != fixture.owner {
				t.Fatal("installed sharing fixture must bind evidence-owner before capture so it joins the retained audience", owner, fixture.owner)
			}
		})
	}
}

func startProcessingReportBrowser(t *testing.T, ctx context.Context, config map[string]any) (*installedLiveBrowser, string) {
	t.Helper()
	output := t.TempDir()
	// Registered before process cleanup: join the browser first, preserve
	// failed synthetic downloads next, then let TempDir remove its copies.
	t.Cleanup(func() {
		fixtures := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
		if !t.Failed() || fixtures == "" {
			return
		}
		archive, err := os.MkdirTemp(filepath.Dir(fixtures), "processing-report-failure-")
		if err != nil {
			t.Log("preserve failed processing report", err)
			return
		}
		for part := 1; part <= 8; part++ {
			name := fmt.Sprintf("processing-report-%d.json", part)
			path := filepath.Join(output, name)
			info, err := os.Stat(path)
			if os.IsNotExist(err) {
				break
			}
			if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
				t.Log("preserve failed processing report: invalid bounded part", part, err)
				break
			}
			raw, err := os.ReadFile(path)
			if err == nil {
				err = os.WriteFile(filepath.Join(archive, name), raw, 0600)
			}
			if err != nil {
				t.Log("preserve failed processing report part", part, err)
				break
			}
		}
		t.Log("failed synthetic processing report downloads preserved", archive)
	})
	config["outputDirectory"] = output
	command, cancel := installedBoundedCommand(ctx, 3*time.Minute, "node", filepath.Join("..", "..", "web", "scripts", "installed-processing-report-browser.mjs"))
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
		in.Close()
		t.Fatal(err)
	}
	diagnostic := &consoleBoundedOutput{}
	command.Stderr = diagnostic
	driver := &installedLiveBrowser{t: t, in: in, events: make(chan json.RawMessage, 8), done: make(chan error, 1), cancel: cancel, cmd: command, diagnostic: diagnostic}
	if err = command.Start(); err != nil {
		cancel()
		in.Close()
		t.Fatal(err)
	}
	go func() {
		scanner := bufio.NewScanner(out)
		scanner.Buffer(make([]byte, 1024), 64<<10)
		for scanner.Scan() {
			raw := append(json.RawMessage(nil), scanner.Bytes()...)
			select {
			case driver.events <- raw:
			case <-ctx.Done():
			}
		}
		close(driver.events)
		err := command.Wait()
		if err == nil {
			err = scanner.Err()
		}
		driver.done <- err
	}()
	t.Cleanup(func() {
		driver.once.Do(func() {
			driver.cancel()
			driver.in.Close()
			installedAwait(t, "processing report browser", driver.done, 30*time.Second)
		})
	})
	driver.send(config)
	return driver, output
}

func readProcessingReportExports(t *testing.T, driver *installedLiveBrowser, directory string, check func(reportPageSummary, value.ProcessingReportPage)) []value.ProcessingReportRecord {
	t.Helper()
	var records []value.ProcessingReportRecord
	seen := map[string]bool{}
	var previous *value.ProcessingReportQuery
	parts := 0
	for {
		var event reportExportEvent
		driver.read(&event)
		if event.Kind == "failed" {
			t.Fatalf("processing report browser stage=%s reason=%s check=%s", event.Stage, event.Reason, event.Check)
		}
		if event.Kind == "complete" {
			if parts == 0 || previous != nil {
				t.Fatal("report browser completed without a terminal exported part")
			}
			break
		}
		parts++
		if event.Kind != "exported" || event.Part != parts || parts > 8 || event.File != fmt.Sprintf("processing-report-%d.json", parts) || event.Bytes < 1 || event.Bytes > 1<<20 {
			t.Fatal("invalid bounded report part summary")
		}
		raw, err := os.ReadFile(filepath.Join(directory, event.File))
		sum := sha256.Sum256(raw)
		if err != nil || int64(len(raw)) != event.Bytes || hex.EncodeToString(sum[:]) != event.SHA256 {
			t.Fatal("downloaded report bytes differ from the browser file", err)
		}
		var exported processingReportExport
		if json.Unmarshal(raw, &exported) != nil || exported.Format != "asservat-processing-inventory/v1" || exported.Part != event.Part ||
			exported.Complete != event.Complete || len(exported.Pages) != len(event.Pages) || len(exported.Pages) == 0 || len(exported.Pages) > 32 {
			t.Fatal("invalid downloaded report document")
		}
		for i, envelope := range exported.Pages {
			summary := event.Pages[i]
			if summary.RequestID != envelope.RequestID || envelope.Status != "ok" || envelope.DataClass != "metadata" ||
				summary.ResponseBytes < 1 || summary.ResponseBytes > contracts.InvestigationOutputLimit {
				t.Fatal("downloaded report page does not match its HTTP response")
			}
			if previous != nil && !reflect.DeepEqual(summary.Query, *previous) {
				t.Fatal("report did not follow the original continuation")
			}
			var page value.ProcessingReportPage
			if json.Unmarshal(envelope.Data, &page) != nil || !page.Valid(summary.Query, page.ObservedAt) {
				t.Fatal("downloaded report page lost canonical source bounds")
			}
			for _, record := range page.Records {
				cursor, _ := json.Marshal(record.Cursor())
				key := page.Section + string(cursor)
				if seen[key] {
					t.Fatal("export repeated a report record", page.Section)
				}
				seen[key] = true
				records = append(records, record)
			}
			check(summary, page)
			previous = page.Next
		}
		if !reflect.DeepEqual(exported.Next, previous) || exported.Complete != (previous == nil) {
			t.Fatal("report document lost terminal or continuation state")
		}
		driver.send(map[string]bool{"continue": true})
	}
	awaitInstalledProcessingBrowser(t, driver)
	return records
}

func installedProcessingReportSource(ctx context.Context, client kubernetes.Interface, namespace, installation string) (*core.ConfigMap, error) {
	deployments, err := client.AppsV1().Deployments(namespace).List(ctx, meta.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("report owner deployment: %w", err)
	}
	configuration := ""
	owners := 0
	for _, deployment := range deployments.Items {
		if deployment.Spec.Template.Labels["asservat.io/private-role"] != "hub-api" {
			continue
		}
		owners++
		for _, volume := range deployment.Spec.Template.Spec.Volumes {
			if volume.Projected == nil {
				continue
			}
			for _, projection := range volume.Projected.Sources {
				if projection.ConfigMap == nil {
					continue
				}
				for _, item := range projection.ConfigMap.Items {
					if item.Key == "deployment.json" && item.Path == "deployment.json" {
						if configuration != "" {
							return nil, errors.New("report owner deployment has ambiguous input projection")
						}
						configuration = projection.ConfigMap.Name
					}
				}
			}
		}
	}
	if owners != 1 || configuration == "" {
		return nil, fmt.Errorf("report owner deployment input unavailable: owners=%d", owners)
	}
	input, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, configuration, meta.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("report owner input: %w", err)
	}
	deployment, err := contracts.DecodeOwnerDeployment(strings.NewReader(input.Data["deployment.json"]))
	if err != nil || deployment.Format != contracts.OwnerDeploymentFormat || deployment.InstallationID != installation || deployment.Public == nil || deployment.Public.Processing == nil {
		return nil, errors.New("report owner processing source input invalid")
	}
	pin := deployment.Public.Processing.Source
	source, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, pin.Name, meta.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("report selected processing source: %w", err)
	}
	if pin.Name == "" || pin.UID == "" || string(source.UID) != pin.UID {
		return nil, errors.New("report selected processing source UID changed")
	}
	return source, nil
}

func installedReportProvenanceMismatch(got, want value.ProcessingReportPage) string {
	var mismatches []string
	for _, field := range []struct{ name, got, want string }{
		{"root_id", got.RootID, want.RootID}, {"installation_id", got.InstallationID, want.InstallationID},
		{"policy_revision.uid", got.PolicyRevision.UID, want.PolicyRevision.UID},
		{"policy_revision.generation", fmt.Sprint(got.PolicyRevision.Generation), fmt.Sprint(want.PolicyRevision.Generation)},
		{"policy_revision.digest", got.PolicyRevision.Digest, want.PolicyRevision.Digest},
		{"processor_declarations", got.ProcessorDeclarations, want.ProcessorDeclarations},
	} {
		if field.got != field.want {
			mismatches = append(mismatches, fmt.Sprintf("%s: got=%q want=%q", field.name, field.got, field.want))
		}
	}
	return strings.Join(mismatches, "; ")
}
