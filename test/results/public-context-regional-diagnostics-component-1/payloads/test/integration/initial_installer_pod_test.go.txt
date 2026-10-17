package integration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// The fixture supplies maintenance/provider authority and writes protected
// Secrets. Product code derives, provisions and retires the purpose SQL roles;
// the actual Restricted executable performs native proofs and activation.
func nativeInitialInstallerPod(t *testing.T, ctx context.Context, f fixture, sql *pgxpool.Pool, tokens map[string]string, bucket, mode, sqlAddress string, sqlTLS *tls.Config) {
	t.Helper()
	if f.WorkerImage == "" || f.NativeProviders.Postgres == "" {
		t.Fatal("native provider fixture missing")
	}
	kc, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(kc)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "initial-pod-" + mode, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	who, err := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	installation, epoch, cluster := custodyID(), custodyID(), custodyID()
	t.Cleanup(func() {
		cleanup, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		if _, err := sql.Exec(cleanup, "DELETE FROM fleet_initial_activation WHERE installation_id=$1", installation); err != nil {
			t.Error(err)
		}
		if _, err := sql.Exec(cleanup, "DELETE FROM fleet_observation WHERE installation_id=$1", installation); err != nil {
			t.Error(err)
		}
		if _, err := sql.Exec(cleanup, "DELETE FROM fleet_trust WHERE installation_id=$1", installation); err != nil {
			t.Error(err)
		}
	})
	p := kube.InitialInstallerWorkloadPlan{Namespace: ns.Name, Name: "installer", WriterAccount: "writer", ProbeAccount: "probe", Configuration: "inputs", Credentials: "providers", Image: f.WorkerImage, Witness: "witness", FleetSource: "fleet", WitnessGuard: ns.Name + "-witness", FleetGuard: ns.Name + "-fleet", WorkloadGuard: ns.Name + "-namespace"}
	w, err := kube.BuildInitialInstallerWorkload(p)
	if err != nil {
		t.Fatal(err)
	}
	accounts := map[string]*core.ServiceAccount{}
	for _, sa := range w.Accounts {
		accounts[sa.Name], err = api.CoreV1().ServiceAccounts(ns.Name).Create(ctx, sa, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range w.Roles {
		if _, err = api.RbacV1().Roles(ns.Name).Create(ctx, r, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range w.Bindings {
		if _, err = api.RbacV1().RoleBindings(ns.Name).Create(ctx, r, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = api.RbacV1().ClusterRoles().Create(ctx, w.ClusterRole, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.RbacV1().ClusterRoleBindings().Create(ctx, w.ClusterBinding, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if mode == "unbound" {
		// Same trusted workload specification, but the authenticated writer is
		// deliberately not Pod-bound. No alternate runtime fallback is allowed.
		v := &w.Pod.Spec.Volumes[0].Projected.Sources
		*v = (*v)[:2]
		(*v)[1].Secret.Items = append((*v)[1].Secret.Items, core.KeyToPath{Key: "kube-writer.token", Path: "kube-writer.token"})
	}
	pod, err := api.CoreV1().Pods(ns.Name).Create(ctx, w.Pod, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pod.Spec.NodeName != "" || len(pod.Spec.SchedulingGates) != 1 {
		t.Fatal("installer launched before protection")
	}
	t.Cleanup(func() {
		cleanup, end := context.WithTimeout(context.Background(), 25*time.Second)
		defer end()
		if err := api.CoreV1().Pods(ns.Name).Delete(cleanup, pod.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &pod.UID}}); err != nil && !apierrors.IsNotFound(err) {
			t.Error(err)
		}
		for cleanup.Err() == nil {
			_, err := api.CoreV1().Pods(ns.Name).Get(cleanup, pod.Name, meta.GetOptions{})
			if apierrors.IsNotFound(err) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Error("installer Pod not removed normally")
	})
	digest := kube.InstallationPodSpecDigest(pod.Spec)
	ref := func(name, uid string) contracts.WorkerObjectReference {
		return contracts.WorkerObjectReference{Name: name, UID: uid}
	}
	nsref := cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}
	adminActors := []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}
	wp := cfg.InitialWorkloadAdministration{Name: p.WorkloadGuard, Configuration: p.Configuration, Witness: p.Witness, FleetSource: p.FleetSource, ControlNamespace: nsref, PodName: pod.Name, PodUID: string(pod.UID), WriterAccount: p.WriterAccount, WriterAccountUID: string(accounts[p.WriterAccount].UID), ProbeAccount: p.ProbeAccount, ProbeAccountUID: string(accounts[p.ProbeAccount].UID), PodSpecDigest: digest, Administrators: adminActors}
	protect := func(policy *admission.ValidatingAdmissionPolicy, binding *admission.ValidatingAdmissionPolicyBinding, actors []cfg.KubernetesActor) contracts.OwnerDeploymentGuard {
		t.Helper()
		policy, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		binding, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		g := contracts.OwnerDeploymentGuard{Name: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion}
		for _, a := range actors {
			g.Administrators = append(g.Administrators, contracts.OwnerDeploymentActor{Kind: a.Kind, Name: a.Name})
		}
		return g
	}
	policy, binding, err := kube.InitialWorkloadAdmission(wp)
	if err != nil {
		t.Fatal(err)
	}
	wg := protect(policy, binding, adminActors)
	fresh, err := kube.FreshInstallationWitnessData(installation, epoch, wp.WriterAccountUID)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := api.CoreV1().ConfigMaps(ns.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: p.Witness}, Data: fresh}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../examples/fleet-settings.json")
	if err != nil {
		t.Fatal(err)
	}
	var fleet map[string]any
	if json.Unmarshal(raw, &fleet) != nil {
		t.Fatal("fleet fixture")
	}
	fleet["installationID"], fleet["issuerEpoch"] = installation, epoch
	raw, _ = json.Marshal(fleet)
	source, err := api.CoreV1().ConfigMaps(ns.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: p.FleetSource}, Data: map[string]string{"fleet.json": string(raw)}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wa := append(append([]cfg.KubernetesActor(nil), adminActors...), cfg.KubernetesActor{Kind: "User", Name: "system:serviceaccount:" + ns.Name + ":" + p.WriterAccount})
	policy, binding, err = kube.InstallationWitnessAdmission(cfg.ConfigMapAdministration{Name: p.WitnessGuard, SourceName: p.Witness, ControlNamespace: nsref, Administrators: wa})
	if err != nil {
		t.Fatal(err)
	}
	witnessGuard := protect(policy, binding, wa)
	policy, binding, err = kube.FleetConfigurationAdmission(cfg.ConfigMapAdministration{Name: p.FleetGuard, SourceName: p.FleetSource, ControlNamespace: nsref, Administrators: adminActors})
	if err != nil {
		t.Fatal(err)
	}
	fleetGuard := protect(policy, binding, adminActors)
	ca := kc.CAData
	if len(ca) == 0 {
		ca, err = os.ReadFile(kc.CAFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	block, _ := pem.Decode(ca)
	if block == nil {
		t.Fatal("API CA unavailable")
	}
	host, portText, err := net.SplitHostPort(f.NativeProviders.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	c := contracts.InitialInstaller{Format: contracts.InitialInstallerFormat, InstallationID: installation, IssuerEpoch: epoch, ClusterID: cluster, Namespace: ref(ns.Name, string(ns.UID)), Witness: ref(witness.Name, string(witness.UID)), WriterAccount: ref(p.WriterAccount, wp.WriterAccountUID), ProbeAccount: ref(p.ProbeAccount, wp.ProbeAccountUID), Pod: ref(pod.Name, string(pod.UID)), PodSpecDigest: hex.EncodeToString(digest[:]), Configuration: p.Configuration, FleetSource: ref(source.Name, string(source.UID)), WitnessGuard: witnessGuard, FleetGuard: fleetGuard, WorkloadGuard: wg, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://kubernetes.default.svc", Roots: [][]byte{block.Bytes}}, Postgres: contracts.OwnerPostgresEndpoint{Host: host, Port: port, Database: "custody_test", Roots: [][]byte{f.NativeProviders.Root}, MaxConnections: 2}, AuditStore: contracts.OwnerAuditStore{Endpoint: f.NativeProviders.S3, Roots: [][]byte{f.NativeProviders.Root}, Region: "us-east-1", Bucket: bucket}, KeyService: contracts.ConfigurationKeyService{Endpoint: f.NativeProviders.KMS, Roots: [][]byte{f.NativeProviders.Root}, AuditMount: "initial-transit", AuditKey: "audit"}}
	raw, err = json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	startupDigest := artifact.Digest(sha256.Sum256(raw))
	input, err := api.CoreV1().ConfigMaps(ns.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: p.Configuration}, Immutable: ptr.To(true), Data: map[string]string{"deployment.json": string(raw)}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// A bounded Secret-bound probe token has no provider/key/activation access.
	// The fixture's administrator issues it; the installer cannot mint tokens.
	anchor, err := api.CoreV1().Secrets(ns.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "probe-lifetime"}, Immutable: ptr.To(true)}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := api.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, p.ProbeAccount, &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: anchor.Name, UID: anchor.UID}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pc := &rest.Config{Host: kc.Host, BearerToken: probe.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}
	probeAPI, err := kubernetes.NewForConfig(pc)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(15 * time.Second)
	for {
		_, err = probeAPI.CoreV1().ConfigMaps(ns.Name).Update(ctx, input.DeepCopy(), meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		if err != nil && strings.Contains(err.Error(), "ValidatingAdmissionPolicy '"+p.WorkloadGuard+"'") {
			break
		}
		if !time.Now().Before(until) {
			t.Fatal("namespace guard not enforcing before credentials", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if mode == "valid" {
		// Fixture-only RBAC permits attacks so these cases exercise namespace
		// admission, not an unrelated RBAC denial. Remove it before launch.
		role, e := api.RbacV1().Roles(ns.Name).Get(ctx, p.Name+"-"+p.ProbeAccount, meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		originalRules := append([]rbac.PolicyRule(nil), role.Rules...)
		role.Rules = append(role.Rules,
			rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
			rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{pod.Name}, Verbs: []string{"update"}},
			rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{p.WriterAccount}, Verbs: []string{"create"}})
		role, e = api.RbacV1().Roles(ns.Name).Update(ctx, role, meta.UpdateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		denied := func(e error) {
			t.Helper()
			if e == nil || !strings.Contains(e.Error(), "ValidatingAdmissionPolicy '"+p.WorkloadGuard+"'") {
				t.Fatal("expected exact namespace denial", e)
			}
		}
		_, e = probeAPI.CoreV1().Pods(ns.Name).Create(ctx, &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "intruder"}, Spec: *w.Pod.Spec.DeepCopy()}, meta.CreateOptions{DryRun: []string{meta.DryRunAll}})
		denied(e)
		_, e = probeAPI.CoreV1().Pods(ns.Name).Update(ctx, pod.DeepCopy(), meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		denied(e)
		_, e = probeAPI.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, p.WriterAccount, &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID}}}, meta.CreateOptions{})
		denied(e)
		role.Rules = originalRules
		if _, e = api.RbacV1().Roles(ns.Name).Update(ctx, role, meta.UpdateOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e = probeAPI.CoreV1().Secrets(ns.Name).Get(ctx, anchor.Name, meta.GetOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("probe has credential read access", e)
		}
	}
	secret := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: p.Credentials}, Immutable: ptr.To(true), Data: map[string][]byte{"audit-wrap.token": []byte(tokens["encrypt"]), "audit-unwrap.token": []byte(tokens["decrypt"]), "kube-probe.token": []byte(probe.Status.Token)}}
	op := initialSQLMaintenance(t, ctx, sql, sqlAddress, sqlTLS)
	sqlPlan, err := postgres.NewInitialSQLCredentials(installation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	state, err := postgres.EncodeInitialSQLCredentials(sqlPlan, startupDigest)
	if err != nil {
		t.Fatal(err)
	}
	adminClient, err := kube.NewPermissionClient(kc, cluster, nsref, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	probeClient, err := kube.NewPermissionClient(pc, cluster, nsref, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	stateStore, err := kube.NewInitialCredentialStateStore(adminClient, probeClient, wp, kube.GuardPin{PolicyUID: wg.PolicyUID, PolicyGeneration: wg.PolicyGeneration, BindingUID: wg.BindingUID, BindingResourceVersion: wg.BindingResourceVersion}, string(input.UID), installation, "sql-credential-state", startupDigest)
	if err != nil {
		t.Fatal(err)
	}
	stateRef, err := stateStore.Create(ctx, state)
	if err != nil {
		t.Fatal("persist SQL secret state", err)
	}
	if replay, err := stateStore.Create(ctx, state); err != nil || replay != stateRef {
		t.Fatal("exact state replay", err)
	}
	otherPlan, err := postgres.NewInitialSQLCredentials(installation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	otherState, err := postgres.EncodeInitialSQLCredentials(otherPlan, startupDigest)
	if err != nil {
		t.Fatal(err)
	}
	_, conflict := stateStore.Create(ctx, otherState)
	clear(otherState)
	if conflict == nil {
		t.Fatal("secret state was overwritten/adopted")
	}
	clear(state)
	stored, err := stateStore.Read(ctx, stateRef)
	if err != nil {
		t.Fatal("read immutable SQL state", err)
	}
	wrongRef := stateRef
	wrongRef.UID = custodyID()
	if wrong, err := stateStore.Read(ctx, wrongRef); err == nil {
		clear(wrong)
		t.Fatal("adopted replacement Secret identity")
	}
	sqlPlan, err = postgres.DecodeInitialSQLCredentials(stored, installation, startupDigest)
	clear(stored)
	if err != nil {
		t.Fatal("SQL state scope", err)
	}
	manager, err := postgres.NewInitialSQLRoles(ctx, op, installation)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Provision(ctx, sqlPlan); err != nil {
		t.Fatal("provision native SQL roles", err)
	}
	t.Cleanup(func() {
		cleanup, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		if err := manager.Retire(cleanup, sqlPlan); err != nil {
			t.Error("retire initial SQL roles", err)
		}
	})
	for role, login := range map[string]postgres.InitialSQLLogin{"prepare": sqlPlan.Preparation, "audit": sqlPlan.Audit, "activate": sqlPlan.Activation} {
		secret.Data["sql-"+role+".json"], _ = json.Marshal(contracts.OwnerSQLCredential{Username: login.Username, Password: login.Password})
	}
	if mode == "wrong-sql-role" {
		// Existing otherwise functional fixture roles do not belong to this
		// installation. File substitution must fail before consuming its witness.
		for _, role := range []string{"prepare", "audit", "activate"} {
			secret.Data["sql-"+role+".json"], _ = json.Marshal(contracts.OwnerSQLCredential{Username: "initial_" + role, Password: "synthetic-initial"})
		}
	}
	secret.Data["audit-storage.json"], _ = json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: "synthetic-only", SecretAccessKey: "synthetic-only-secret"})
	if mode == "unbound" {
		token, err := api.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, p.WriterAccount, &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		secret.Data["kube-writer.token"] = []byte(token.Status.Token)
	}
	if _, err = api.CoreV1().Secrets(ns.Name).Create(ctx, secret, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, v := range secret.Data {
		clear(v)
	}
	if mode == "missing-guard" {
		if err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, p.WorkloadGuard, meta.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		if leaked, err := stateStore.Read(ctx, stateRef); err == nil {
			clear(leaked)
			t.Fatal("credential read without namespace protection")
		}
	}
	pod.Spec.SchedulingGates = nil
	pod, err = api.CoreV1().Pods(ns.Name).Update(ctx, pod, meta.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(45 * time.Second)
	for {
		current, err := api.CoreV1().Pods(ns.Name).Get(ctx, pod.Name, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if current.UID != pod.UID {
			t.Fatal("installer Pod replaced")
		}
		if current.Status.Phase == core.PodSucceeded || current.Status.Phase == core.PodFailed {
			logs, e := api.CoreV1().Pods(ns.Name).GetLogs(pod.Name, &core.PodLogOptions{LimitBytes: ptr.To(int64(4096))}).Stream(ctx)
			if e == nil {
				b, _ := io.ReadAll(io.LimitReader(logs, 4096))
				logs.Close()
				t.Log("installer output", string(b))
			}
			if len(current.Status.ContainerStatuses) != 1 {
				t.Fatal("missing actual process status")
			}
			status := current.Status.ContainerStatuses[0]
			if !strings.HasSuffix(status.ImageID, strings.Split(f.WorkerImage, "@")[1]) || status.RestartCount != 0 || status.State.Terminated == nil {
				t.Fatal("installer process/image identity")
			}
			if mode == "valid" && (current.Status.Phase != core.PodSucceeded || status.State.Terminated.ExitCode != 0) {
				t.Fatal("native installer did not activate", current.Status.Phase, status.State.Terminated.ExitCode)
			}
			if mode != "valid" && status.State.Terminated.ExitCode == 0 {
				t.Fatal("invalid installer reported success")
			}
			t.Log("native initial-installer Pod", pod.UID, "image", status.ImageID, "exit", status.State.Terminated.ExitCode)
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("installer did not terminate", current.Status.Phase, current.Status.Conditions)
		}
		time.Sleep(100 * time.Millisecond)
	}
	var count int
	if err = sql.QueryRow(ctx, "SELECT count(*) FROM fleet_initial_activation WHERE installation_id=$1 AND activated_at IS NOT NULL AND audit_receipt_json IS NOT NULL", installation).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if mode == "valid" {
		if count != 1 {
			t.Fatal("native process did not persist audited activation")
		}
		var blocked bool
		if err = sql.QueryRow(ctx, "SELECT recovery_blocked FROM fleet_current_trust WHERE installation_id=$1", installation).Scan(&blocked); err != nil || blocked {
			t.Fatal("database incarnation not activated", err)
		}
		historicalScope := value.InstallationWitnessScope{InstallationID: c.InstallationID, IssuerEpoch: c.IssuerEpoch, ClusterID: c.ClusterID, Namespace: c.Namespace.Name, NamespaceUID: c.Namespace.UID, Name: c.Witness.Name, UID: c.Witness.UID, WriterAccount: c.WriterAccount.Name, WriterAccountUID: c.WriterAccount.UID}
		historicalAuthority, err := kube.NewInitialInstallationReadProtection(adminClient, probeClient, wp, kube.GuardPin{PolicyUID: wg.PolicyUID, PolicyGeneration: wg.PolicyGeneration, BindingUID: wg.BindingUID, BindingResourceVersion: wg.BindingResourceVersion}, string(input.UID), historicalScope, startupDigest)
		if err != nil {
			t.Fatal(err)
		}
		qualifyNativeInitialHistoricalRead(t, ctx, sql, sqlAddress, sqlTLS, historicalAuthority, historicalScope, startupDigest)
	} else {
		if err = sql.QueryRow(ctx, "SELECT count(*) FROM fleet_initial_activation").Scan(&count); err != nil || count != 0 {
			t.Fatal("failed startup consumed installation attempt", err)
		}
		cm, err := api.CoreV1().ConfigMaps(ns.Name).Get(ctx, witness.Name, meta.GetOptions{})
		if err != nil || cm.Immutable != nil && *cm.Immutable {
			t.Fatal("failed startup consumed witness", err)
		}
	}
	if mode != "missing-guard" {
		retained, err := stateStore.Read(ctx, stateRef)
		if err != nil {
			t.Fatal("retirement state read after termination", err)
		}
		retirePlan, err := postgres.DecodeInitialSQLCredentials(retained, installation, startupDigest)
		clear(retained)
		if err != nil {
			t.Fatal(err)
		}
		if err = manager.Retire(ctx, retirePlan); err != nil {
			t.Fatal("retire from persisted state", err)
		}
		late, err := postgres.EncodeInitialSQLCredentials(sqlPlan, startupDigest)
		if err != nil {
			t.Fatal(err)
		}
		_, err = stateStore.Create(ctx, late)
		clear(late)
		if err == nil {
			t.Fatal("credential creation after Pod launch")
		}
	}
	if err = api.CoreV1().Secrets(ns.Name).Delete(ctx, anchor.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &anchor.UID}}); err != nil {
		t.Fatal(err)
	}
	// Native successful-token authentication is cached. Retirement must confirm
	// actual denial; deleting the anchor does not imply instantaneous revocation.
	retired := time.Now()
	for {
		_, err = probeAPI.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
		if apierrors.IsUnauthorized(err) {
			break
		}
		if err != nil || time.Since(retired) > 20*time.Second {
			t.Fatal("probe credential retirement not confirmed", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Log("probe token retirement observed after", time.Since(retired))
}
