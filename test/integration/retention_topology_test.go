package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/privacy"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Real API immutability, least-privilege GET and UID/content binding. Initial
// topology approval/enrollment remains an explicit synthetic installer input.
func qualifyRetentionTopology(t *testing.T, ctx context.Context, native kubernetes.Interface, client *kube.PermissionClient, namespace, root string, hub privacy.PolicySourceRef) {
	t.Helper()
	for _, local := range []bool{false, true} {
		name := "retention-topology"
		wire := contracts.RetentionTopologySettings{SchemaVersion: "retention-topology/v1", Revision: 1, RootID: root, TargetClusterID: hub.ClusterID, Hub: contracts.RetentionPolicySource{ClusterID: hub.ClusterID, ControlNamespaceUID: hub.ControlNamespaceUID, ProtectionSHA256: hex.EncodeToString(hub.ProtectionDigest[:])}}
		if local {
			name += "-local"
			wire.Local = &contracts.RetentionPolicySource{ClusterID: hub.ClusterID, ControlNamespaceUID: "another-protected-control-namespace", ProtectionSHA256: wire.Hub.ProtectionSHA256}
		}
		b, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		canonical := jsontext.Value(b)
		if err = canonical.Canonicalize(); err != nil {
			t.Fatal(err)
		}
		pin := artifact.Digest(sha256.Sum256(canonical))
		immutable := true
		cm, err := native.CoreV1().ConfigMaps(namespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: name}, Immutable: &immutable, Data: map[string]string{"topology.json": string(b)}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		role, err := native.RbacV1().Roles(namespace).Get(ctx, "retention-reader", meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		role.Rules = append(role.Rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{name}, Verbs: []string{"get"}})
		if _, err = native.RbacV1().Roles(namespace).Update(ctx, role, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		reader, err := kube.NewRetentionTopologyClient(client, name, string(cm.UID), root, hub.ClusterID, pin)
		if err != nil {
			t.Fatal(err)
		}
		out, err := reader.RetentionTopology(ctx, hub.ClusterID)
		want := 1
		if local {
			want = 2
		}
		if err != nil || !out.Valid(time.Now()) || len(out.Sources) != want || out.Sources[0] != hub {
			t.Fatal("pinned topology", out, err)
		}
		// Even a native administrator cannot silently change the accepted data.
		changed := cm.DeepCopy()
		changed.Data["topology.json"] = `{}`
		if _, err = native.CoreV1().ConfigMaps(namespace).Update(ctx, changed, meta.UpdateOptions{}); !apierrors.IsInvalid(err) {
			t.Fatal("immutable data rewritten", err)
		}
		if _, err = native.CoreV1().ConfigMaps(namespace).Patch(ctx, name, types.MergePatchType, []byte(`{"immutable":false}`), meta.PatchOptions{}); !apierrors.IsInvalid(err) {
			t.Fatal("immutability removed", err)
		}
		if _, err = native.CoreV1().ConfigMaps(namespace).Patch(ctx, name, types.MergePatchType, []byte(`{"metadata":{"annotations":{"test.asservat.io/note":"unchanged-data"}}}`), meta.PatchOptions{}); err != nil {
			t.Fatal(err)
		}
		after, err := reader.RetentionTopology(ctx, hub.ClusterID)
		if err != nil || after.Revision != out.Revision {
			t.Fatal("metadata churn changed topology", err)
		}
		if err = native.CoreV1().ConfigMaps(namespace).Delete(ctx, name, meta.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err = reader.RetentionTopology(ctx, hub.ClusterID); err == nil {
			t.Fatal("missing topology silently reduced sources")
		}
		replacement := &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: name}, Immutable: &immutable, Data: map[string]string{"topology.json": string(b)}}
		if _, err = native.CoreV1().ConfigMaps(namespace).Create(ctx, replacement, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err = reader.RetentionTopology(ctx, hub.ClusterID); err == nil {
			t.Fatal("same-name replacement accepted without requalification")
		}
	}
}
