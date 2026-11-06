package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/targets"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

// SavedLogClient uses only existing whole-Pod get and pods/log get permissions.
// Unlike the pod-status transport it streams bounded log bodies instead of
// placing a two-MiB wrapper around every API response.
type SavedLogClient struct{ client typedcore.CoreV1Interface }

func NewSavedLogClient(config *rest.Config) (*SavedLogClient, error) {
	if config == nil || config.Insecure {
		return nil, artifact.ErrInvalid
	}
	u, err := url.Parse(config.Host)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path != "" && u.Path != "/" {
		return nil, artifact.ErrInvalid
	}
	c := rest.CopyConfig(config)
	c.Timeout, c.QPS, c.Burst = 5*time.Second, 20, 20
	c.WarningHandlerWithContext = rest.NoWarnings{}
	c.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	c.DisableCompression = true
	httpClient, err := rest.HTTPClientFor(c)
	if err != nil {
		return nil, ErrContextUnavailable
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrContextUnavailable }
	client, err := typedcore.NewForConfigAndClient(c, httpClient)
	if err != nil {
		return nil, ErrContextUnavailable
	}
	return &SavedLogClient{client: client}, nil
}

// SavedLogSnapshot is observed provenance, never permission or a historical
// continuity proof. Its private entries prevent caller-chosen container paths.
type SavedLogSnapshot struct {
	pin         artifact.PinnedPod
	origins     []artifact.LogOrigin
	available   []bool
	fingerprint artifact.Digest
}

func (s SavedLogSnapshot) Origins() []artifact.LogOrigin {
	out := append([]artifact.LogOrigin(nil), s.origins...)
	for i := range out {
		if out[i].RuntimeID != nil {
			v := *out[i].RuntimeID
			out[i].RuntimeID = &v
		}
		if out[i].RestartCount != nil {
			v := *out[i].RestartCount
			out[i].RestartCount = &v
		}
	}
	return out
}

// SameInstances permits publication only when both observations retain the
// original Pod and participating current/previous instance fingerprints. API
// logs has no UID precondition; a detected change invalidates the whole artifact.
func (s SavedLogSnapshot) SameInstances(other SavedLogSnapshot) bool {
	return s.pin == other.pin && s.fingerprint != (artifact.Digest{}) && s.fingerprint == other.fingerprint
}

func savedLogPinValid(pin artifact.PinnedPod) bool {
	return len(validation.IsDNS1123Label(pin.Namespace)) == 0 && len(validation.IsDNS1123Subdomain(pin.Name)) == 0 && pin.UID != "" && pin.NamespaceUID != ""
}

func savedLogPodMatches(pin artifact.PinnedPod, pod *core.Pod) bool {
	if pod == nil || pod.Namespace != pin.Namespace || pod.Name != pin.Name || string(pod.UID) != pin.UID {
		return false
	}
	if pin.ControllerUID != "" {
		found := false
		for _, owner := range pod.OwnerReferences {
			if owner.Controller != nil && *owner.Controller {
				if found || string(owner.UID) != pin.ControllerUID {
					return false
				}
				found = true
			}
		}
		return found
	}
	return true
}

func (c *SavedLogClient) Snapshot(ctx context.Context, pin artifact.PinnedPod) (SavedLogSnapshot, error) {
	var zero SavedLogSnapshot
	if c == nil || c.client == nil || ctx == nil || ctx.Err() != nil || !savedLogPinValid(pin) {
		return zero, artifact.ErrInvalid
	}
	body, err := c.client.RESTClient().Get().Namespace(pin.Namespace).Resource("pods").Name(pin.Name).MaxRetries(0).Stream(ctx)
	if err != nil {
		return zero, contextError(err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(body, (2<<20)+1))
	closeErr := body.Close()
	defer clear(raw)
	if readErr != nil || closeErr != nil || len(raw) > 2<<20 || ctx.Err() != nil {
		return zero, ErrContextUnavailable
	}
	var pod core.Pod
	if json.Unmarshal(raw, &pod) != nil || !savedLogPodMatches(pin, &pod) {
		return zero, ErrTargetChanged
	}
	return savedLogSnapshot(pin, &pod)
}

func savedLogSnapshot(pin artifact.PinnedPod, pod *core.Pod) (SavedLogSnapshot, error) {
	var out SavedLogSnapshot
	if !savedLogPinValid(pin) || !savedLogPodMatches(pin, pod) {
		return out, ErrTargetChanged
	}
	type member struct {
		Kind, Name, Current, Previous string
		Restarts                      int32
		CurrentAvailable              bool
	}
	var members []member
	add := func(kind string, names []string, statuses []core.ContainerStatus) error {
		seen := map[string]bool{}
		byName := map[string]core.ContainerStatus{}
		for _, s := range statuses {
			if _, duplicate := byName[s.Name]; duplicate || s.RestartCount < 0 {
				return ErrContextUnavailable
			}
			byName[s.Name] = s
		}
		for _, name := range names {
			if seen[name] || len(validation.IsDNS1123Label(name)) != 0 {
				return ErrContextUnavailable
			}
			seen[name] = true
			s := byName[name]
			m := member{Kind: kind, Name: name, Current: s.ContainerID, Restarts: s.RestartCount}
			if t := s.LastTerminationState.Terminated; t != nil {
				m.Previous = t.ContainerID
			}
			m.CurrentAvailable = s.ContainerID != "" || s.State.Running != nil || s.State.Terminated != nil
			members = append(members, m)
		}
		for name := range byName {
			if !seen[name] {
				return ErrContextUnavailable
			}
		}
		return nil
	}
	names := func(containers []core.Container) []string {
		out := make([]string, len(containers))
		for i, c := range containers {
			out[i] = c.Name
		}
		return out
	}
	if err := add("regular", names(pod.Spec.Containers), pod.Status.ContainerStatuses); err != nil {
		return out, err
	}
	if err := add("init", names(pod.Spec.InitContainers), pod.Status.InitContainerStatuses); err != nil {
		return out, err
	}
	ephemeral := make([]string, len(pod.Spec.EphemeralContainers))
	for i, c := range pod.Spec.EphemeralContainers {
		ephemeral[i] = c.Name
	}
	if err := add("ephemeral", ephemeral, pod.Status.EphemeralContainerStatuses); err != nil {
		return out, err
	}
	if len(members) == 0 || len(members) > artifact.LogMaxOrigins/2 {
		return out, targets.ErrLimit
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].Kind != members[j].Kind {
			return members[i].Kind < members[j].Kind
		}
		return members[i].Name < members[j].Name
	})
	out.pin = pin
	for _, m := range members {
		for _, previous := range []bool{false, true} {
			origin := artifact.LogOrigin{Record: "origin", OriginID: uint16(len(out.origins)), ContainerKind: m.Kind, ContainerName: m.Name, Source: "current", Stream: "combined"}
			id, count, available := m.Current, uint32(m.Restarts), m.CurrentAvailable
			if previous {
				origin.Source, id, available = "previous", m.Previous, m.Restarts > 0 || m.Previous != ""
				if m.Restarts > 0 {
					count--
				}
			}
			if id != "" {
				origin.RuntimeID = &id
			}
			if !previous || available {
				origin.RestartCount = &count
			}
			if !origin.WellFormed() {
				return SavedLogSnapshot{}, ErrContextUnavailable
			}
			out.origins = append(out.origins, origin)
			out.available = append(out.available, available)
		}
	}
	raw, _ := json.Marshal(members)
	out.fingerprint = artifact.Digest(sha256.Sum256(raw))
	return out, nil
}

func (s SavedLogSnapshot) Available(origin uint16) bool {
	return int(origin) < len(s.available) && s.available[origin]
}

// Open requests one observed current/previous source. The caller must keep the
// original total deadline, fairly bound bytes and compare a final Snapshot
// before publishing. Nil Stream is Kubernetes All, never invented stdout.
func (c *SavedLogClient) Open(ctx context.Context, snapshot SavedLogSnapshot, originID uint16, since time.Time, limit int64) (io.ReadCloser, error) {
	if c == nil || c.client == nil || ctx == nil || ctx.Err() != nil || !savedLogPinValid(snapshot.pin) || !snapshot.Available(originID) || since.IsZero() || limit <= 0 || limit > artifact.LogNativeLimit {
		return nil, artifact.ErrInvalid
	}
	origin := snapshot.origins[originID]
	options := &core.PodLogOptions{Container: origin.ContainerName, Previous: origin.Source == "previous", Timestamps: true, SinceTime: &meta.Time{Time: since}, LimitBytes: &limit}
	body, err := c.client.Pods(snapshot.pin.Namespace).GetLogs(snapshot.pin.Name, options).MaxRetries(0).Stream(ctx)
	if err != nil {
		return nil, contextError(err)
	}
	return &boundedBody{ReadCloser: body, remaining: limit + 1}, nil
}
