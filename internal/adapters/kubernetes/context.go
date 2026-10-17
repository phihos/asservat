// Package kubernetes contains Kubernetes protocol adapters, not access policy.
package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const ContextFormat = artifact.ContextFormat

// ProjectionDefinition is versioned, immutable and covered by the manifest's
// projectionDigest. It does not permit free text or arbitrary JSON pointers.
const ProjectionDefinition = artifact.ContextProjectionDefinition

var ErrTargetChanged = errors.New("pinned pod identity changed or unavailable")
var ErrContextUnavailable = errors.New("bounded pod status unavailable")
var ErrContextDenied = errors.New("Kubernetes denied pod status access")

func contextError(err error) error {
	if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
		return ErrContextDenied
	}
	if apierrors.IsNotFound(err) {
		return ErrTargetChanged
	}
	return ErrContextUnavailable
}

type statusProjection struct {
	Format           string    `json:"format"`
	NamespaceUID     string    `json:"namespaceUID"`
	PodUID           string    `json:"podUID"`
	ResourceVersion  string    `json:"resourceVersion"`
	ObservedAt       time.Time `json:"observedAt"`
	Phase            string    `json:"phase"`
	Ready            string    `json:"ready"`
	Initialized      string    `json:"initialized"`
	Scheduled        string    `json:"scheduled"`
	RuntimeInstances int       `json:"runtimeInstances"`
	Running          int       `json:"running"`
	Waiting          int       `json:"waiting"`
	Terminated       int       `json:"terminated"`
	Restarts         int64     `json:"restarts"`
}

func ProjectionDigest() artifact.Digest {
	return artifact.Digest(sha256.Sum256([]byte(ProjectionDefinition)))
}

type ContextCollector struct {
	client         typedcore.CoreV1Interface
	executionClass artifact.ContextExecutionClass
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, ErrContextUnavailable
	}
	n, err := b.ReadCloser.Read(p[:min(int64(len(p)), b.remaining)])
	b.remaining -= int64(n)
	return n, err
}

type contextTransport struct{ http.RoundTripper }

func (t contextTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	v, err := t.RoundTripper.RoundTrip(r)
	if v != nil && v.Body != nil {
		v.Body = &boundedBody{v.Body, 2 << 20}
	}
	return v, err
}

// NewContextClient keeps client-go authentication/TLS but applies hard response
// and request bounds. Its config is selected by bootstrap, never by a user tool.
func NewContextClient(config *rest.Config) (*ContextCollector, error) {
	return newContextClient(config, artifact.ContextNodeExecution)
}

// NewAPIContextClient is selected only by protected regional composition. It
// reads the fixed Pod projection without requiring a node assignment or access
// to Node objects, exec, logs, files or another acquisition mechanism.
func NewAPIContextClient(config *rest.Config) (*ContextCollector, error) {
	return newContextClient(config, artifact.ContextAPIExecution)
}

func newContextClient(config *rest.Config, class artifact.ContextExecutionClass) (*ContextCollector, error) {
	if config == nil || config.Insecure {
		return nil, artifact.ErrInvalid
	}
	u, err := url.Parse(config.Host)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, artifact.ErrInvalid
	}
	c := rest.CopyConfig(config)
	c.Timeout, c.QPS, c.Burst = 5*time.Second, 5, 5
	c.WarningHandlerWithContext = rest.NoWarnings{}
	c.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	c.DisableCompression = true
	c.Wrap(func(t http.RoundTripper) http.RoundTripper { return contextTransport{t} })
	client, err := rest.HTTPClientFor(c)
	if err != nil {
		return nil, ErrContextUnavailable
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrContextUnavailable }
	api, err := typedcore.NewForConfigAndClient(c, client)
	if err != nil {
		return nil, ErrContextUnavailable
	}
	return &ContextCollector{client: api, executionClass: class}, nil
}

func NewContextCollector(c typedcore.CoreV1Interface) (*ContextCollector, error) {
	if c == nil {
		return nil, artifact.ErrInvalid
	}
	return &ContextCollector{client: c}, nil
}

// Capture reads API state only. The future execution service must first verify
// the accepted pod scope, current rights, capacity, audit, deadline and prepared
// encryption keys. It is deliberately not registered as a public command yet.
// Configure the client with an explicit request timeout/response-size ceiling.
func (c *ContextCollector) Capture(ctx context.Context, pin artifact.PinnedPod) ([]byte, error) {
	if len(validation.IsDNS1123Label(pin.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(pin.Name)) != 0 || len(pin.NamespaceUID) == 0 || len(pin.UID) == 0 || !c.executionClass.Valid() || (c.executionClass == artifact.ContextNodeExecution && len(pin.NodeName) == 0) || (c.executionClass == artifact.ContextAPIExecution && pin.NodeName != "") {
		return nil, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ns, err := c.client.Namespaces().Get(ctx, pin.Namespace, meta.GetOptions{})
	if err != nil {
		return nil, contextError(err)
	}
	if string(ns.UID) != pin.NamespaceUID {
		return nil, ErrTargetChanged
	}
	p, err := c.client.Pods(pin.Namespace).Get(ctx, pin.Name, meta.GetOptions{})
	if err != nil {
		return nil, contextError(err)
	}
	if string(p.UID) != pin.UID || p.Namespace != pin.Namespace || p.Name != pin.Name || (c.executionClass == artifact.ContextNodeExecution && p.Spec.NodeName != pin.NodeName) {
		return nil, ErrTargetChanged
	}
	owner := meta.GetControllerOf(p)
	if (owner == nil && pin.ControllerUID != "") || (owner != nil && (pin.ControllerUID == "" || string(owner.UID) != pin.ControllerUID)) {
		return nil, ErrTargetChanged
	}
	if len(p.ResourceVersion) == 0 || len(p.ResourceVersion) > 128 || len(p.Status.Conditions) > 32 || len(p.Status.ContainerStatuses)+len(p.Status.InitContainerStatuses)+len(p.Status.EphemeralContainerStatuses) > 64 {
		return nil, ErrContextUnavailable
	}
	v := statusProjection{Format: ContextFormat, NamespaceUID: pin.NamespaceUID, PodUID: pin.UID, ResourceVersion: p.ResourceVersion, ObservedAt: time.Now().UTC(), Phase: "Unknown", Ready: "Unknown", Initialized: "Unknown", Scheduled: "Unknown"}
	switch p.Status.Phase {
	case core.PodPending, core.PodRunning, core.PodSucceeded, core.PodFailed, core.PodUnknown:
		v.Phase = string(p.Status.Phase)
	}
	for _, condition := range p.Status.Conditions {
		s := "Unknown"
		if condition.Status == core.ConditionTrue || condition.Status == core.ConditionFalse {
			s = string(condition.Status)
		}
		switch condition.Type {
		case core.PodReady:
			v.Ready = s
		case core.PodInitialized:
			v.Initialized = s
		case core.PodScheduled:
			v.Scheduled = s
		}
	}
	for _, statuses := range [][]core.ContainerStatus{p.Status.ContainerStatuses, p.Status.InitContainerStatuses, p.Status.EphemeralContainerStatuses} {
		for _, s := range statuses {
			if s.RestartCount < 0 {
				return nil, ErrContextUnavailable
			}
			v.RuntimeInstances++
			v.Restarts += int64(s.RestartCount)
			if s.State.Running != nil {
				v.Running++
			}
			if s.State.Waiting != nil {
				v.Waiting++
			}
			if s.State.Terminated != nil {
				v.Terminated++
			}
		}
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) > 4096 {
		return nil, ErrContextUnavailable
	}
	return b, nil
}
