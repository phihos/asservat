package integration

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

func (o *initialRuntimeNativeOwner) observeIdentity(t *testing.T, ctx context.Context, api kubernetes.Interface, config *pgx.ConnConfig, original *apps.Deployment, accepted *postgres.OwnerConfigurations, witness *providerWorkerWitness) {
	t.Helper()
	end := o.providers.trace.phase(t, "actual-owner-original-pod-and-paired-registration")
	defer end()
	pod, replica, image := providerOwnerOriginalPod(t, ctx, api, original, o.root.Input().ServiceAccount.UID)
	pool, registry := o.registry(t, ctx, api, config)
	defer pool.Close()
	var binding fleet.OwnerBinding
	awaitProviderWorker(t, ctx, 45*time.Second, "original owner paired activated identities and encrypted audit", func(call context.Context) bool {
		providerWorkerRequireRunning(t, call, api, pod, image)
		observed, err := accepted.ReadOwnerConfiguration(call)
		if err != nil {
			return false
		}
		if !observed.Valid(time.Now()) || observed.Configuration.Revision.UID != o.root.Input().OwnerConfigurationUID || !sameNativeOwnerRoots(observed.Configuration.IssuerRoots, o.providers.issuerRoots) {
			t.Fatal("owner current accepted original source unavailable")
		}
		rows, err := pool.Query(call, `SELECT enrollment_json,audit_receipt_json FROM hub_owner_enrollment WHERE installation_id=$1 AND cluster_id=$2 AND pod_uid=$3 AND retired_at IS NULL ORDER BY usage LIMIT 3`, o.root.Input().InstallationID, o.root.Input().ClusterID, string(pod.UID))
		if err != nil {
			t.Fatal("original owner enrollment read", err)
		}
		type originalEnrollment struct {
			enrollment fleet.OwnerEnrollment
			receipt    audit.Receipt
		}
		entries := make([]originalEnrollment, 0, 2)
		pending := false
		for rows.Next() {
			var raw, receipt []byte
			if err = rows.Scan(&raw, &receipt); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			var e originalEnrollment
			if json.Unmarshal(raw, &e.enrollment) != nil || !e.enrollment.Valid() {
				rows.Close()
				t.Fatal("actual owner enrollment malformed")
			}
			if len(receipt) == 0 {
				pending = true
			} else if json.Unmarshal(receipt, &e.receipt) != nil || !e.receipt.ValidOwnerEnrollment(e.enrollment) {
				rows.Close()
				t.Fatal("actual owner enrollment acknowledgement malformed")
			}
			entries = append(entries, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) > 2 {
			t.Fatal("original owner Pod acquired extra process registrations")
		}
		if len(entries) != 2 || pending {
			return false
		}
		if entries[0].enrollment.Usage != "client" || entries[1].enrollment.Usage != "server" || entries[0].enrollment.Binding != entries[1].enrollment.Binding {
			t.Fatal("owner purposes did not share one process epoch")
		}
		selected := entries[0].enrollment.Binding
		if binding != (fleet.OwnerBinding{}) && binding != selected {
			t.Fatal("owner replaced original selected process")
		}
		binding = selected
		if binding.PodUID != string(pod.UID) || binding.InstallationID != o.root.Input().InstallationID || binding.ClusterID != o.root.Input().ClusterID || binding.IssuerEpoch != observed.Configuration.Pool.IssuerEpoch {
			t.Fatal("owner registration binding changed original Pod/pool")
		}
		for _, entry := range entries {
			e := entry.enrollment
			if e.Pod != pod.Name || e.ReplicaSetUID != string(replica.UID) || e.ReplicaSet != replica.Name || e.Pool != observed.Configuration.Pool || e.SourceUID != observed.Configuration.Revision.UID {
				t.Fatal("owner enrollment changed original controller/source")
			}
			var attemptRaw, certificateRaw, receiptRaw []byte
			err = pool.QueryRow(call, `SELECT attempt_json,certificate_json,audit_receipt_json FROM hub_owner_certificate WHERE enrollment_id=$1 AND activated_at IS NOT NULL ORDER BY epoch DESC,ordinal DESC LIMIT 1`, e.ID).Scan(&attemptRaw, &certificateRaw, &receiptRaw)
			if errors.Is(err, pgx.ErrNoRows) {
				return false
			}
			if err != nil {
				t.Fatal("actual active certificate read", err)
			}
			var attempt fleet.OwnerCertificateAttempt
			var signed fleet.IssuedOwnerCertificate
			var receipt audit.Receipt
			if json.Unmarshal(attemptRaw, &attempt) != nil || attempt.Enrollment != e || !attempt.Valid(attempt.Permit.CheckedAt) || json.Unmarshal(certificateRaw, &signed) != nil || !attempt.Permit.Matches(signed) || json.Unmarshal(receiptRaw, &receipt) != nil || !receipt.ValidOwnerCertificate(audit.OwnerCertificate{Attempt: attempt, Certificate: signed.Certificate}) {
				t.Fatal("activated owner certificate/audit disagrees with original attempt")
			}
			providerOwnerVerifyCertificate(t, signed, e, observed)
			if err := witness.verifyOwnerEnrollment(call, entry.enrollment, entry.receipt); err != nil {
				t.Fatal("independent original enrollment audit", err)
			}
			if err := witness.verifyOwnerCertificate(call, audit.OwnerCertificate{Attempt: attempt, Certificate: signed.Certificate}, receipt); err != nil {
				t.Fatal("independent original certificate audit", err)
			}
			current, err := registry.ReadOwnerRegistration(call, signed.Certificate)
			if err != nil || current.Enrollment != e || !current.Valid(time.Now()) {
				t.Fatal("actual current owner registration unavailable after audit readback", err)
			}
			t.Logf("original owner purpose=%s pod=%s process=%s registration-remaining=%s source-age=%s original-sign-window=%s enrollment-version=%s certificate-version=%s", e.Usage, pod.UID, e.Binding.ProcessEpoch, time.Until(current.FreshUntil), time.Since(current.Configuration.ObservedAt), attempt.Permit.SignBefore.Sub(attempt.Permit.CheckedAt), entry.receipt.Version, receipt.Version)
		}
		providerWorkerRequireRunning(t, call, api, pod, image)
		if call.Err() != nil || !observed.Valid(time.Now()) {
			t.Fatal("owner identity witness expired before final process/source check")
		}
		return true
	})
	t.Logf("original owner identity running deployment=%s replicaSet=%s pod=%s imageID=%s process=%s; actual paired registration, no fabricated TLS connection or Ready assertion", original.UID, replica.UID, pod.UID, image, binding.ProcessEpoch)
}

func providerOwnerOriginalPod(t *testing.T, ctx context.Context, api kubernetes.Interface, original *apps.Deployment, accountUID string) (*core.Pod, *apps.ReplicaSet, string) {
	t.Helper()
	pin, err := kube.ConnectorAPITemplateDigest(original.Spec.Template)
	if err != nil {
		t.Fatal("original owner template", err)
	}
	selector := labels.SelectorFromSet(original.Spec.Selector.MatchLabels).String()
	var pod *core.Pod
	var replica *apps.ReplicaSet
	var image string
	awaitProviderWorker(t, ctx, 45*time.Second, "original owner product process", func(call context.Context) bool {
		list, err := api.CoreV1().Pods(original.Namespace).List(call, meta.ListOptions{LabelSelector: selector, Limit: 3})
		if err != nil {
			return false
		}
		if list.Continue != "" || len(list.Items) > 1 {
			t.Fatal("owner acquired unexpected Pod population")
		}
		if len(list.Items) != 1 {
			if pod != nil {
				t.Fatal("original owner Pod disappeared while awaiting readiness")
			}
			return false
		}
		v := &list.Items[0]
		if v.UID == "" || v.DeletionTimestamp != nil || pod != nil && (v.UID != pod.UID || v.Name != pod.Name) {
			t.Fatal("owner replaced or deleted original admitted Pod")
		}
		// Pin immediately, before any blocking dependent GET can return a
		// transient failure. Readiness cannot adopt a later replacement.
		if pod == nil {
			pod = v.DeepCopy()
		}
		current, err := api.AppsV1().Deployments(original.Namespace).Get(call, original.Name, meta.GetOptions{})
		want := original.Spec.DeepCopy()
		one := int32(1)
		want.Replicas = &one
		if apierrors.IsNotFound(err) {
			t.Fatal("original owner Deployment disappeared")
		}
		if err != nil {
			return false
		}
		if current.UID != original.UID || current.DeletionTimestamp != nil || !reflect.DeepEqual(current.Spec, *want) {
			t.Fatal("owner original launched Deployment changed or is deleting")
		}
		controller := meta.GetControllerOf(v)
		firstController := meta.GetControllerOf(pod)
		if controller == nil || firstController == nil || controller.UID == "" || controller.Name == "" || controller.Kind != "ReplicaSet" || controller.APIVersion != apps.SchemeGroupVersion.String() || controller.UID != firstController.UID || controller.Name != firstController.Name {
			t.Fatal("original owner ReplicaSet identity absent or changed")
		}
		rs, err := api.AppsV1().ReplicaSets(original.Namespace).Get(call, controller.Name, meta.GetOptions{})
		if apierrors.IsNotFound(err) && replica != nil {
			t.Fatal("original owner ReplicaSet disappeared")
		}
		if err != nil {
			return false
		}
		if rs.UID == "" || rs.DeletionTimestamp != nil || replica != nil && (rs.UID != replica.UID || rs.Name != replica.Name) {
			t.Fatal("owner original ReplicaSet replaced or deleting")
		}
		if replica == nil {
			replica = rs.DeepCopy()
		}
		owner := meta.GetControllerOf(rs)
		if rs.UID != controller.UID || owner == nil || owner.Kind != "Deployment" || owner.APIVersion != apps.SchemeGroupVersion.String() || owner.UID != original.UID || owner.Name != original.Name {
			t.Fatal("owner original controller changed")
		}
		template := rs.Spec.Template.DeepCopy()
		hash := template.Labels[apps.DefaultDeploymentUniqueLabelKey]
		if hash == "" || v.Labels[apps.DefaultDeploymentUniqueLabelKey] != hash || !maps.Equal(v.Annotations, template.Annotations) || !maps.Equal(v.Labels, template.Labels) {
			t.Fatal("owner original Pod metadata changed")
		}
		delete(template.Labels, apps.DefaultDeploymentUniqueLabelKey)
		got, err := kube.ConnectorAPITemplateDigest(*template)
		if err != nil || got != pin {
			t.Fatal("owner ReplicaSet template changed", err)
		}
		native := core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: maps.Clone(v.Labels), Annotations: maps.Clone(v.Annotations)}, Spec: *v.Spec.DeepCopy()}
		delete(native.Labels, apps.DefaultDeploymentUniqueLabelKey)
		native.Spec.NodeName = ""
		got, err = kube.ConnectorAPITemplateDigest(native)
		if err != nil || got != pin {
			t.Fatal("owner original Pod template changed", err)
		}
		account, err := api.CoreV1().ServiceAccounts(original.Namespace).Get(call, v.Spec.ServiceAccountName, meta.GetOptions{})
		if err != nil || account.DeletionTimestamp != nil || string(account.UID) != accountUID || account.Name != original.Spec.Template.Spec.ServiceAccountName {
			t.Fatal("owner original account replaced", err)
		}
		pod, replica = v.DeepCopy(), rs.DeepCopy()
		if len(v.Status.ContainerStatuses) != 1 {
			return false
		}
		status := v.Status.ContainerStatuses[0]
		if status.RestartCount != 0 || status.State.Terminated != nil {
			exit := int32(-1)
			if status.State.Terminated != nil {
				exit = status.State.Terminated.ExitCode
			}
			for _, line := range originalOwnerStartupLogDiagnostics(call, api, v) {
				t.Log("original owner process diagnostic:", line)
			}
			t.Fatalf("original owner process stopped before identity: restarts=%d exit=%d", status.RestartCount, exit)
		}
		if status.State.Running == nil || status.ImageID == "" {
			return false
		}
		parts := strings.Split(original.Spec.Template.Spec.Containers[0].Image, "@sha256:")
		if len(parts) != 2 || !strings.HasSuffix(status.ImageID, "sha256:"+parts[1]) {
			t.Fatal("owner actual image differs from original compiled image")
		}
		image = status.ImageID
		return true
	})
	return pod, replica, image
}

// Independent certificate-body verification, never a fabricated TLS state or
// claim that reading a public certificate proves a new handshake.
func providerOwnerVerifyCertificate(t *testing.T, signed fleet.IssuedOwnerCertificate, enrollment fleet.OwnerEnrollment, observed fleet.OwnerConfigurationObservation) {
	t.Helper()
	leaf, err := x509.ParseCertificate(signed.DER)
	if err != nil || artifact.Digest(sha256.Sum256(signed.DER)) != signed.Certificate.Digest || signed.Certificate.Binding != enrollment.Binding || signed.Certificate.Usage != enrollment.Usage || !signed.Certificate.Valid(time.Now()) || !leaf.NotAfter.Equal(signed.Certificate.NotAfter) || !leaf.NotBefore.Equal(signed.Certificate.NotBefore) || artifact.Digest(sha256.Sum256(leaf.RawSubjectPublicKeyInfo)) != enrollment.PublicKeyDigest {
		t.Fatal("original owner public certificate mismatch", err)
	}
	uri, err := mtls.OwnerURI(enrollment.Binding)
	if err != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != uri.String() || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatal("owner public certificate profile changed", err)
	}
	roots, _, err := mtls.OwnerTrustRoots(observed.Configuration.IssuerRoots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	intermediate := x509.NewCertPool()
	for _, der := range signed.ChainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		intermediate.AddCert(c)
	}
	usage := x509.ExtKeyUsageClientAuth
	if enrollment.Usage == "server" {
		usage = x509.ExtKeyUsageServerAuth
		name, err := mtls.OwnerServerName(enrollment.Binding)
		if err != nil || leaf.VerifyHostname(name) != nil {
			t.Fatal("original owner server name", err)
		}
		common, err := mtls.OwnerBootstrapServerName(enrollment.Pool)
		if err != nil || leaf.VerifyHostname(common) != nil {
			t.Fatal("original owner bootstrap name", err)
		}
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediate, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		t.Fatal("independent owner original issuer verification", err)
	}
}

func (w *providerWorkerWitness) ownerAuditBytes(ctx context.Context, r audit.Receipt) ([]byte, error) {
	if r.Version == "" || r.Version == "null" || r.Bytes < 1 || r.Bytes > 128<<10 {
		return nil, errors.New("owner audit receipt lacks bounded immutable version")
	}
	p, err := w.store.Pin(objectstore.Object{Key: r.Key, VersionID: r.Version, ETag: r.ETag, Bytes: r.Bytes, SHA256: r.SHA256})
	if err != nil {
		return nil, err
	}
	raw, err := p.ReadRange(ctx, 0, r.Bytes)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(raw) != r.SHA256 {
		clear(raw)
		return nil, errors.New("owner audit ciphertext digest changed")
	}
	return raw, nil
}
func (w *providerWorkerWitness) verifyOwnerEnrollment(ctx context.Context, e fleet.OwnerEnrollment, r audit.Receipt) error {
	if !r.ValidOwnerEnrollment(e) {
		return errors.New("owner enrollment receipt invalid")
	}
	raw, err := w.ownerAuditBytes(ctx, r)
	if err != nil {
		return err
	}
	defer clear(raw)
	return framed.VerifyOwnerEnrollment(ctx, w.opener, e, raw)
}
func (w *providerWorkerWitness) verifyOwnerCertificate(ctx context.Context, c audit.OwnerCertificate, r audit.Receipt) error {
	if !r.ValidOwnerCertificate(c) {
		return errors.New("owner certificate receipt invalid")
	}
	raw, err := w.ownerAuditBytes(ctx, r)
	if err != nil {
		return err
	}
	defer clear(raw)
	return framed.VerifyOwnerCertificate(ctx, w.opener, c, raw)
}

// Failure diagnostics only. These reads cannot grant authority, adopt another
// Pod, retry an effect or change the original failing verdict. Both log streams
// share the original caller's at-most-five-second bound and 8 KiB each. Only
// exact closed startup records survive; arbitrary stdout/stderr is discarded.
func originalOwnerStartupLogDiagnostics(ctx context.Context, api kubernetes.Interface, original *core.Pod) []string {
	if ctx == nil || ctx.Err() != nil || api == nil || original == nil || original.UID == "" {
		return nil
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pods := api.CoreV1().Pods(original.Namespace)
	before, err := pods.Get(call, original.Name, meta.GetOptions{})
	if err != nil || before.UID != original.UID {
		return nil
	}
	var out []string
	for _, previous := range []bool{false, true} {
		limit, tail := int64(8192), int64(32)
		stream, e := pods.GetLogs(original.Name, &core.PodLogOptions{Container: "hub", Previous: previous, LimitBytes: &limit, TailLines: &tail, Follow: false}).Stream(call)
		if e != nil {
			continue
		}
		raw, e := io.ReadAll(io.LimitReader(stream, 8193))
		closeErr := stream.Close()
		if e == nil && closeErr == nil && len(raw) <= 8192 {
			for _, line := range strings.Split(string(raw), "\n") {
				if safe, ok := bootstrap.OwnerStartupDiagnosticLine(line); ok {
					scope := "current"
					if previous {
						scope = "previous"
					}
					out = append(out, scope+": "+safe)
					// One closed startup failure per process invocation is sufficient.
					break
				}
			}
		}
		clear(raw)
	}
	after, err := pods.Get(call, original.Name, meta.GetOptions{})
	if err != nil || after.UID != original.UID || call.Err() != nil {
		return nil
	}
	return out
}
