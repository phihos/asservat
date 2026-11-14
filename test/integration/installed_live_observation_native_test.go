package integration

// Installed qualification uses only the real public/session/source pipelines.
// Administrator SQL is read-only evidence, never an authority producer.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	v "asservat.local/asservat/internal/domain/live"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

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
	rootLimits := contracts.LiveRootSettings{Watches: 3, PrincipalWatches: 2, WorkloadWatches: 3, Rate: 1 << 20, Burst: 1 << 20}
	if installedJourneyFocus() == "ongoing-incident" {
		rootLimits.Watches, rootLimits.WorkloadWatches = 2, 2
	}
	out.LiveRead = &contracts.LiveReadSettings{Root: rootLimits, Projections: []string{v.Packet, v.Syscall, v.HTTP}, Clients: clients, Ceilings: []contracts.LiveReadCeiling{{ClusterID: cluster, Duration: 120, Output: 1 << 20, Rate: 64 << 10, Rows: 20, Buffer: 128 << 10, RowAge: 30, Replay: 5}}}
	encoded, err := json.Marshal(out)
	if err != nil || len(encoded) > contracts.DownloadEnvironmentMaxBytes {
		return contracts.DownloadEnvironmentSettings{}, errors.New("delivery settings bound")
	}
	return out, nil
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
