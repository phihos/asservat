package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// This reader runs at trusted control mediation, not in a collector with a
// token-review credential. Expected dispatch identities are independently pinned.
type DownloadPeerAttester struct{ *AcquisitionPeerAttester }

// The shared attester establishes only exact admitted workload identity. Parent
// authority is independently enforced by the download or approved-query ledger.
type AcquisitionPeerAttester struct {
	client   *PermissionClient
	expected value.AcquisitionWorkerBinding
	tokens   app.DownloadPeerToken
}

// The production source obtains its expected identity from the protected SQL
// dispatch reader. Fixed-pin construction remains useful for isolated checks.
type DispatchedDownloadPeerAttester struct {
	client   *PermissionClient
	bindings app.DownloadWorkerBindings
	tokens   app.DownloadPeerToken
}

var _ app.DownloadPeerProofReader = (*DispatchedDownloadPeerAttester)(nil)

func NewDispatchedDownloadPeerAttester(c *PermissionClient, b app.DownloadWorkerBindings, t app.DownloadPeerToken) (*DispatchedDownloadPeerAttester, error) {
	if c == nil || b == nil || t == nil {
		return nil, artifact.ErrInvalid
	}
	return &DispatchedDownloadPeerAttester{c, b, t}, nil
}
func (s *DispatchedDownloadPeerAttester) ReadDownloadPeerProof(ctx context.Context, session string, peer value.KeyPeer) (value.KeyWorkerProof, error) {
	var zero value.KeyWorkerProof
	if s == nil || ctx == nil {
		return zero, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	started := s.client.now()
	observation, e := s.bindings.ReadDownloadWorkerIdentity(ctx, session, peer)
	w := observation.Worker
	if e != nil || !observation.Valid(s.client.now()) || w.Intent.SessionID != session || w.Binding.PodUID != peer.PeerID {
		return zero, artifact.ErrInvalid
	}
	profile := w.Intent.Profile
	if s.client.clusterID != profile.ClusterID || s.client.control.Name != profile.Namespace || s.client.control.UID != profile.NamespaceUID {
		return zero, artifact.ErrInvalid
	}
	// This private instance only reads pinned sources; it has no effect guard.
	jobs := &DownloadWorkerJobs{client: s.client, profile: profile}
	if jobs.sources(ctx) != nil {
		return zero, artifact.ErrInvalid
	}
	attester, e := NewDownloadPeerAttester(s.client, w.Binding, s.tokens)
	if e != nil {
		return zero, e
	}
	p, e := attester.ReadDownloadPeerProof(ctx, session, peer)
	if e != nil {
		return zero, e
	}
	if jobs.sources(ctx) != nil || s.client.current(ctx, started, 5*time.Second) != nil {
		return zero, artifact.ErrInvalid
	}
	p.ObservedAt = started
	p.FreshUntil = identity.Earlier(observation.FreshUntil, identity.Earlier(p.FreshUntil, identity.Earlier(started.Add(5*time.Second), w.Intent.RunUntil)))
	if !p.Valid(s.client.now()) {
		return zero, artifact.ErrInvalid
	}
	return p, nil
}

var _ app.DownloadPeerProofReader = (*DownloadPeerAttester)(nil)

func NewDownloadPeerAttester(c *PermissionClient, b value.KeyWorkerBinding, tokens app.DownloadPeerToken) (*DownloadPeerAttester, error) {
	if !b.Valid() {
		return nil, artifact.ErrInvalid
	}
	a, err := NewAcquisitionPeerAttester(c, b.Acquisition(), tokens)
	if err != nil {
		return nil, err
	}
	return &DownloadPeerAttester{a}, nil
}
func NewAcquisitionPeerAttester(c *PermissionClient, b value.AcquisitionWorkerBinding, tokens app.DownloadPeerToken) (*AcquisitionPeerAttester, error) {
	if c == nil || tokens == nil || !b.Valid() || c.clusterID != b.ClusterID || c.control.Name != b.Namespace || c.control.UID != b.NamespaceUID || len(validation.IsDNS1123Label(b.Namespace)) != 0 || len(validation.IsDNS1123Label(b.Job)) != 0 || len(validation.IsDNS1123Subdomain(b.Pod)) != 0 || len(validation.IsDNS1123Subdomain(b.ServiceAccount)) != 0 {
		return nil, artifact.ErrInvalid
	}
	return &AcquisitionPeerAttester{c, b, tokens}, nil
}
func DownloadPeerAudience(installation string) string {
	return "https://asservat." + installation + "/key-worker-enrollment"
}

// WorkerSpecDigest covers the entire API-defaulted pod/Job spec. Only trusted
// dispatch may pin this digest after validating the intended workload profile.
func WorkerSpecDigest(kind string, spec []byte) (artifact.Digest, error) {
	if (kind != "Pod" && kind != "Job") || len(spec) == 0 || len(spec) > 128<<10 || spec[0] != '{' {
		return artifact.Digest{}, artifact.ErrInvalid
	}
	c := jsontext.Value(bytes.Clone(spec))
	defer clear(c)
	if c.Canonicalize() != nil {
		return artifact.Digest{}, artifact.ErrInvalid
	}
	h := sha256.New()
	h.Write([]byte("asservat-key-worker-spec/v1\x00" + kind + "\x00"))
	h.Write(c)
	var out artifact.Digest
	copy(out[:], h.Sum(nil))
	return out, nil
}

// JWT crypto/private Kubernetes claims are verified by TokenReview. Read only
// standard exp/iat after that verification to keep the observation inside the
// original token lifetime; opaque and legacy/unbounded tokens are unsupported.
func reviewedTokenExpiry(token []byte, now time.Time) (time.Time, error) {
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		return time.Time{}, artifact.ErrInvalid
	}
	payload, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	defer clear(payload)
	if e != nil || len(payload) > 12<<10 || base64.RawURLEncoding.EncodeToString(payload) != parts[1] || !jsontext.Value(payload).IsValid() {
		return time.Time{}, artifact.ErrInvalid
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil {
		return time.Time{}, artifact.ErrInvalid
	}
	var exp, iat int64
	if json.Unmarshal(claims["exp"], &exp) != nil || json.Unmarshal(claims["iat"], &iat) != nil || exp <= iat || iat <= 0 || exp-iat > 3600 || now.Before(time.Unix(iat, 0)) || !now.Before(time.Unix(exp, 0)) {
		return time.Time{}, artifact.ErrInvalid
	}
	return time.Unix(exp, 0).UTC(), nil
}
func (s *AcquisitionPeerAttester) review(ctx context.Context, token []byte) error {
	b := s.expected
	pod, err := reviewBoundPodToken(ctx, s.client, token, DownloadPeerAudience(b.InstallationID), b.Namespace, b.ServiceAccount, b.ServiceAccountUID, b.PodUID)
	if err != nil || pod != b.Pod {
		return artifact.ErrInvalid
	}
	return nil
}

// Kubernetes verifies signatures and private bound-object claims. Callers must
// additionally re-read live objects and preserve the token's original expiry.
func reviewBoundPodToken(ctx context.Context, client *PermissionClient, token []byte, audience, namespace, account, accountUID, podUID string) (string, error) {
	// This byte buffer and its response can contain a token; neither leaves the
	// adapter or enters an underlying server error returned to callers.
	body, e := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": map[string]any{"token": string(token), "audiences": []string{audience}}})
	defer clear(body)
	if e != nil {
		return "", artifact.ErrInvalid
	}
	raw, e := client.api.Post().AbsPath("/apis/authentication.k8s.io/v1/tokenreviews").Body(body).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil || permissionJSON(raw, 64<<10, 16384) != nil {
		return "", artifact.ErrInvalid
	}
	var reply struct {
		APIVersion, Kind string
		Status           struct {
			Authenticated bool
			Error         string
			Audiences     []string
			User          struct {
				Username, UID string
				Groups        []string
				Extra         map[string][]string
			}
		}
	}
	if json.Unmarshal(raw, &reply) != nil || reply.APIVersion != "authentication.k8s.io/v1" || reply.Kind != "TokenReview" || !reply.Status.Authenticated || reply.Status.Error != "" || len(reply.Status.Audiences) != 1 || reply.Status.Audiences[0] != audience {
		return "", artifact.ErrInvalid
	}
	u := reply.Status.User
	if u.Username != "system:serviceaccount:"+namespace+":"+account || u.UID != accountUID || len(u.Extra["authentication.kubernetes.io/pod-name"]) != 1 || len(u.Extra["authentication.kubernetes.io/pod-uid"]) != 1 || u.Extra["authentication.kubernetes.io/pod-uid"][0] != podUID {
		return "", artifact.ErrInvalid
	}
	pod := u.Extra["authentication.kubernetes.io/pod-name"][0]
	if pod == "" || len(validation.IsDNS1123Subdomain(pod)) != 0 {
		return "", artifact.ErrInvalid
	}
	return pod, nil
}
func (s *AcquisitionPeerAttester) object(ctx context.Context, kind, name, uid string) (map[string]json.RawMessage, error) {
	b := s.expected
	resource, version := "serviceaccounts", "v1"
	prefix := "/api/v1/namespaces/" + b.Namespace + "/"
	switch kind {
	case "Pod":
		resource = "pods"
	case "Job":
		resource = "jobs"
		version = "batch/v1"
		prefix = "/apis/batch/v1/namespaces/" + b.Namespace + "/"
	}
	raw, e := s.client.raw(ctx, prefix+resource+"/"+name, nil)
	defer clear(raw)
	if e != nil || len(raw) > 256<<10 {
		return nil, artifact.ErrInvalid
	}
	var fields map[string]json.RawMessage
	var meta struct {
		Name, Namespace, UID, ResourceVersion string
		DeletionTimestamp                     *string
	}
	if json.Unmarshal(raw, &fields) != nil || string(fields["apiVersion"]) != `"`+version+`"` || string(fields["kind"]) != `"`+kind+`"` || json.Unmarshal(fields["metadata"], &meta) != nil || meta.Name != name || meta.Namespace != b.Namespace || meta.UID != uid || !identity.Text(meta.ResourceVersion, 128) || meta.DeletionTimestamp != nil {
		return nil, artifact.ErrInvalid
	}
	return fields, nil
}
func (s *AcquisitionPeerAttester) live(ctx context.Context) error {
	b := s.expected
	ns, e := s.client.namespace(ctx, s.client.control)
	if e != nil || ns.Deleting {
		return artifact.ErrInvalid
	}
	if _, e = s.object(ctx, "ServiceAccount", b.ServiceAccount, b.ServiceAccountUID); e != nil {
		return e
	}
	job, e := s.object(ctx, "Job", b.Job, b.JobUID)
	if e != nil {
		return e
	}
	defer func() {
		for _, v := range job {
			clear(v)
		}
	}()
	jd, e := WorkerSpecDigest("Job", job["spec"])
	if e != nil || jd != b.JobSpec {
		return artifact.ErrInvalid
	}
	var js struct {
		CompletionTime *string
		Conditions     []struct{ Type, Status string }
	}
	if json.Unmarshal(job["status"], &js) != nil || js.CompletionTime != nil {
		return artifact.ErrInvalid
	}
	for _, c := range js.Conditions {
		if (c.Type == "Complete" || c.Type == "Failed" || c.Type == "FailureTarget" || c.Type == "SuccessCriteriaMet") && c.Status == "True" {
			return artifact.ErrInvalid
		}
	}
	var spec struct {
		Suspend  bool
		Template struct {
			Spec struct{ ServiceAccountName string }
		}
	}
	if json.Unmarshal(job["spec"], &spec) != nil || spec.Suspend || spec.Template.Spec.ServiceAccountName != b.ServiceAccount {
		return artifact.ErrInvalid
	}
	pod, e := s.object(ctx, "Pod", b.Pod, b.PodUID)
	if e != nil {
		return e
	}
	defer func() {
		for _, v := range pod {
			clear(v)
		}
	}()
	pd, e := WorkerSpecDigest("Pod", pod["spec"])
	if e != nil || pd != b.PodSpec {
		return artifact.ErrInvalid
	}
	var ps struct {
		ServiceAccountName            string
		HostNetwork, HostPID, HostIPC bool
	}
	var status struct{ Phase string }
	var metadata struct {
		OwnerReferences []struct {
			APIVersion, Kind, Name, UID string
			Controller                  bool
		}
	}
	if json.Unmarshal(pod["spec"], &ps) != nil || ps.ServiceAccountName != b.ServiceAccount || ps.HostNetwork || ps.HostPID || ps.HostIPC || json.Unmarshal(pod["status"], &status) != nil || (status.Phase != "Pending" && status.Phase != "Running") || json.Unmarshal(pod["metadata"], &metadata) != nil {
		return artifact.ErrInvalid
	}
	controllers := 0
	for _, o := range metadata.OwnerReferences {
		if o.Controller {
			controllers++
			if o.APIVersion != "batch/v1" || o.Kind != "Job" || o.Name != b.Job || o.UID != b.JobUID {
				return artifact.ErrInvalid
			}
		}
	}
	if controllers != 1 {
		return artifact.ErrInvalid
	}
	return nil
}
func (s *DownloadPeerAttester) ReadDownloadPeerProof(ctx context.Context, session string, peer value.KeyPeer) (value.KeyWorkerProof, error) {
	if s == nil || s.AcquisitionPeerAttester == nil {
		return value.KeyWorkerProof{}, artifact.ErrInvalid
	}
	p, err := s.ReadAcquisitionPeerProof(ctx, value.AcquisitionParent{Purpose: value.AcquisitionDownload, ID: session}, peer)
	if err != nil {
		return value.KeyWorkerProof{}, err
	}
	binding, ok := p.Binding.DownloadBinding()
	if !ok {
		return value.KeyWorkerProof{}, artifact.ErrInvalid
	}
	return value.KeyWorkerProof{Binding: binding, Peer: p.Peer, TokenDigest: p.TokenDigest, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil}, nil
}
func (s *AcquisitionPeerAttester) ReadAcquisitionPeerProof(ctx context.Context, parent value.AcquisitionParent, peer value.KeyPeer) (value.AcquisitionPeerProof, error) {
	var zero value.AcquisitionPeerProof
	if s == nil || ctx == nil || ctx.Err() != nil || !parent.Valid() || parent != s.expected.Parent || peer.InstallationID != s.expected.InstallationID || peer.PeerID != s.expected.PodUID || peer.Role != "acquisition" || !peer.Valid(s.client.now()) {
		return zero, artifact.ErrInvalid
	}
	digest, started, until, err := s.observeToken(ctx)
	if err != nil {
		return zero, err
	}
	p := value.AcquisitionPeerProof{Binding: s.expected, Peer: peer, TokenDigest: digest, ObservedAt: started, FreshUntil: identity.Earlier(until, peer.NotAfter)}
	if !p.Valid(s.client.now()) {
		return zero, artifact.ErrInvalid
	}
	return p, nil
}

// Shared by initial enrollment and certificate-bound key observations. Neither
// path fabricates a certificate to get through the bootstrap check.
func (s *AcquisitionPeerAttester) observeToken(ctx context.Context) (artifact.Digest, time.Time, time.Time, error) {
	var zero artifact.Digest
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := s.client.now()
	token, e := s.tokens.ReadDownloadPeerToken(ctx)
	defer clear(token)
	if e != nil || len(token) == 0 || len(token) > 16<<10 || bytes.IndexAny(token, "\r\n\t ") >= 0 || s.review(ctx, token) != nil {
		return zero, time.Time{}, time.Time{}, artifact.ErrInvalid
	}
	expiry, e := reviewedTokenExpiry(token, s.client.now())
	if e != nil {
		return zero, time.Time{}, time.Time{}, artifact.ErrInvalid
	}
	if s.live(ctx) != nil || s.review(ctx, token) != nil || s.live(ctx) != nil || s.client.current(ctx, started, 5*time.Second) != nil {
		return zero, time.Time{}, time.Time{}, artifact.ErrInvalid
	}
	until := identity.Earlier(started.Add(5*time.Second), expiry)
	if !s.client.now().Before(until) {
		return zero, time.Time{}, time.Time{}, artifact.ErrInvalid
	}
	return artifact.Digest(sha256.Sum256(token)), started, until, nil
}
