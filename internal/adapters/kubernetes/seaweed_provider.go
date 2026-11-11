package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"
)

var ErrSeaweedProvider = errors.New("bundled object store provider unavailable")

type seaweedProviderFailure string

func (e seaweedProviderFailure) Error() string     { return ErrSeaweedProvider.Error() }
func (e seaweedProviderFailure) Unwrap() error     { return ErrSeaweedProvider }
func (e seaweedProviderFailure) FixedStep() string { return string(e) }

// This fixed command contains neither credentials nor a digest. The expected
// digest arrives only on private stdin. Direct Secret projection can lag CAS;
// SIGHUP must not race that projection. One bounded exec, no extra process/watch.
const seaweedReloadScript = `set -eu
[ -x /usr/bin/weed ] && [ -x /bin/kill ]
command -v sha256sum >/dev/null
command -v sleep >/dev/null
[ /proc/1/exe -ef /usr/bin/weed ]
IFS= read -r expected
[ "${#expected}" -eq 64 ]
case "$expected" in *[!0-9a-f]*|'') exit 64;; esac
n=0
while [ "$n" -lt 120 ]; do
  actual=$(sha256sum /run/asservat/objectstore-iam/s3.json)
  actual=${actual%% *}
  if [ "$actual" = "$expected" ]; then
    exec /bin/kill -HUP 1
  fi
  n=$((n + 1))
  sleep 1
done
exit 75
`

// SeaweedReloadCommand returns the same fixed command for the provider and its
// exact-image component qualification. Private expected digest is stdin only.
func SeaweedReloadCommand() []string { return []string{"/bin/sh", "-ec", seaweedReloadScript} }

type SeaweedProvider struct {
	api    rest.Interface
	target contracts.SeaweedProviderTarget
	exec   func(context.Context, []byte) error
}

var seaweedImagePin = regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$`)

func validSeaweedTarget(t contracts.SeaweedProviderTarget) bool {
	if !authorization.UUID(t.InstallationID) || len(validation.IsDNS1123Label(t.Namespace)) != 0 || !seaweedImagePin.MatchString(t.Image) || !slices.Equal(t.ExpectedArgs, providerconfig.SeaweedServerArgs()) {
		return false
	}
	for _, r := range []contracts.WorkerObjectReference{t.StatefulSet, t.Pod, t.Config} {
		if len(validation.IsDNS1123Subdomain(r.Name)) != 0 || !authorization.UUID(r.UID) {
			return false
		}
	}
	return t.Pod.Name == t.StatefulSet.Name+"-0" && t.Config.Name == t.StatefulSet.Name+"-iam"
}
func NewSeaweedProvider(config *rest.Config, target contracts.SeaweedProviderTarget) (*SeaweedProvider, error) {
	if !validSeaweedTarget(target) {
		return nil, seaweedProviderFailure("target")
	}
	api, e := newBoundedAPI(config)
	if e != nil {
		return nil, seaweedProviderFailure("api")
	}
	cfg := rest.CopyConfig(config)
	cfg.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	cfg.Timeout = 0
	transport, upgrader, e := spdy.RoundTripperFor(cfg)
	if e != nil {
		return nil, seaweedProviderFailure("exec-transport")
	}
	s := &SeaweedProvider{api: api, target: target}
	s.exec = func(ctx context.Context, input []byte) error {
		u, e := url.Parse(cfg.Host)
		if e != nil {
			return e
		}
		u.Path = "/api/v1/namespaces/" + target.Namespace + "/pods/" + target.Pod.Name + "/exec"
		q := url.Values{"container": {"seaweed"}, "stdin": {"true"}, "stdout": {"true"}, "stderr": {"true"}, "tty": {"false"}, "command": SeaweedReloadCommand()}
		u.RawQuery = q.Encode()
		executor, e := remotecommand.NewSPDYExecutorRejectRedirects(transport, upgrader, http.MethodPost, u)
		if e != nil {
			return e
		}
		return executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: bytes.NewReader(input), Stdout: io.Discard, Stderr: io.Discard})
	}
	return s, nil
}
func (s *SeaweedProvider) read(ctx context.Context, path string, out any) error {
	raw, e := s.api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil || len(raw) > 2<<20 || strictGuardJSON(raw, out) != nil {
		return ErrSeaweedProvider
	}
	return nil
}
func (s *SeaweedProvider) snapshot(ctx context.Context) (*core.Secret, error) {
	t := s.target
	base := "/api/v1/namespaces/" + t.Namespace
	var st apps.StatefulSet
	if s.read(ctx, "/apis/apps/v1/namespaces/"+t.Namespace+"/statefulsets/"+t.StatefulSet.Name, &st) != nil || string(st.UID) != t.StatefulSet.UID || st.DeletionTimestamp != nil {
		return nil, seaweedProviderFailure("statefulset")
	}
	var p core.Pod
	if s.read(ctx, base+"/pods/"+t.Pod.Name, &p) != nil || string(p.UID) != t.Pod.UID || p.DeletionTimestamp != nil || p.Status.Phase != core.PodRunning || len(p.Spec.Containers) != 1 || len(p.Spec.InitContainers) != 0 || len(p.Spec.EphemeralContainers) != 0 || len(p.OwnerReferences) != 1 {
		return nil, seaweedProviderFailure("pod")
	}
	owner := p.OwnerReferences[0]
	if owner.Kind != "StatefulSet" || owner.Name != st.Name || string(owner.UID) != t.StatefulSet.UID || owner.Controller == nil || !*owner.Controller {
		return nil, seaweedProviderFailure("pod-owner")
	}
	c := p.Spec.Containers[0]
	if c.Name != "seaweed" || c.Image != t.Image || !slices.Equal(c.Command, []string{"/usr/bin/weed"}) || !slices.Equal(c.Args, t.ExpectedArgs) || len(p.Status.ContainerStatuses) != 1 {
		return nil, seaweedProviderFailure("image-command")
	}
	cs := p.Status.ContainerStatuses[0]
	if cs.Name != "seaweed" || !cs.Ready || cs.State.Running == nil || !strings.Contains(cs.ImageID, "@sha256:") {
		return nil, seaweedProviderFailure("process")
	}
	mount := ""
	for _, m := range c.VolumeMounts {
		if m.MountPath == "/run/asservat/objectstore-iam" && m.ReadOnly && m.SubPath == "" && m.SubPathExpr == "" {
			mount = m.Name
		}
	}
	found := false
	for _, v := range p.Spec.Volumes {
		if v.Name == mount && v.Secret != nil && v.Secret.SecretName == t.Config.Name && len(v.Secret.Items) == 1 && v.Secret.Items[0].Key == providerconfig.SeaweedConfigKey && v.Secret.Items[0].Path == providerconfig.SeaweedConfigKey {
			found = true
		}
	}
	if !found {
		return nil, seaweedProviderFailure("source-mount")
	}
	var secret core.Secret
	if s.read(ctx, base+"/secrets/"+t.Config.Name, &secret) != nil || string(secret.UID) != t.Config.UID || secret.ResourceVersion == "" || secret.DeletionTimestamp != nil || secret.Type != core.SecretTypeOpaque || len(secret.Data) != 1 || len(secret.StringData) != 0 || len(secret.Data[providerconfig.SeaweedConfigKey]) == 0 || len(secret.Data[providerconfig.SeaweedConfigKey]) > providerconfig.SeaweedConfigLimit || secret.Immutable != nil && *secret.Immutable {
		return nil, seaweedProviderFailure("config")
	}
	return &secret, nil
}

// Reload changes only an original mutable IAM Secret, preserves retained keys,
// waits for its direct projection, and signals the exact running provider. This
// is NOT phase success: the caller must perform authenticated scoped S3 probes.
func (s *SeaweedProvider) Reload(ctx context.Context, config []byte) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !validSeaweedTarget(s.target) || len(config) == 0 || len(config) > providerconfig.SeaweedConfigLimit {
		return seaweedProviderFailure("input")
	}
	ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	secret, e := s.snapshot(ctx)
	if e != nil {
		return e
	}
	defer clear(secret.Data[providerconfig.SeaweedConfigKey])
	if e = providerconfig.ValidateSeaweedConfigTransition(secret.Data[providerconfig.SeaweedConfigKey], config); e != nil {
		return seaweedProviderFailure("retained-config")
	}
	if !bytes.Equal(secret.Data[providerconfig.SeaweedConfigKey], config) {
		secret.Data = map[string][]byte{providerconfig.SeaweedConfigKey: bytes.Clone(config)}
		defer clear(secret.Data[providerconfig.SeaweedConfigKey])
		raw, e := json.Marshal(secret)
		if e != nil {
			return seaweedProviderFailure("config-encoding")
		}
		defer clear(raw)
		result, e := s.api.Put().AbsPath("/api/v1/namespaces/"+s.target.Namespace+"/secrets/"+s.target.Config.Name).Param("fieldValidation", "Strict").Body(raw).MaxRetries(0).DoRaw(ctx)
		clear(result)
		// An unknown CAS response permits only exact readback, never another write.
		current, readErr := s.snapshot(ctx)
		if readErr != nil {
			return seaweedProviderFailure("config-readback")
		}
		defer clear(current.Data[providerconfig.SeaweedConfigKey])
		if !bytes.Equal(current.Data[providerconfig.SeaweedConfigKey], config) {
			_ = e
			return seaweedProviderFailure("config-cas")
		}
	}
	hash := sha256.Sum256(config)
	input := []byte(hex.EncodeToString(hash[:]) + "\n")
	defer clear(input)
	if s.exec == nil || s.exec(ctx, input) != nil {
		return seaweedProviderFailure("projection-reload")
	}
	current, e := s.snapshot(ctx)
	if e != nil {
		return e
	}
	defer clear(current.Data[providerconfig.SeaweedConfigKey])
	if ctx.Err() != nil || !bytes.Equal(current.Data[providerconfig.SeaweedConfigKey], config) {
		return seaweedProviderFailure("final")
	}
	return nil
}
