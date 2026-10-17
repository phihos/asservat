package kubernetes

import (
	"encoding/hex"
	"strings"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

const InitialInstallerSchedulingGate = "asservat.io/installation-protected"

type InitialInstallerWorkloadPlan struct {
	RegistryAuthentication                                                          string
	WriterAudience                                                                  string
	Namespace, Name, WriterAccount, ProbeAccount, Configuration, Credentials, Image string
	Witness, FleetSource, WitnessGuard, FleetGuard, WorkloadGuard                   string
}
type InitialInstallerWorkload struct {
	Pod            *core.Pod
	Accounts       []*core.ServiceAccount
	Roles          []*rbac.Role
	Bindings       []*rbac.RoleBinding
	ClusterRole    *rbac.ClusterRole
	ClusterBinding *rbac.ClusterRoleBinding
}

// Builds an inert single Pod. A trusted provisioner must persist its UID and
// server-defaulted spec, install/qualify protection, provision immutable inputs
// and only then remove its scheduling gate. There is no automatic restart or
// replacement on a missing/failed Pod, nor any authority conferred by this plan.
func BuildInitialInstallerWorkload(p InitialInstallerWorkloadPlan) (*InitialInstallerWorkload, error) {
	if p.WriterAudience != "" && !identity.Text(p.WriterAudience, 256) || len(validation.IsDNS1123Label(p.Namespace)) != 0 || len(validation.IsDNS1123Label(p.Name)) != 0 || p.WriterAccount == p.ProbeAccount {
		return nil, cfg.ErrInvalid
	}
	for _, n := range []string{p.WriterAccount, p.ProbeAccount, p.Configuration, p.Credentials, p.Witness, p.FleetSource, p.WitnessGuard, p.FleetGuard, p.WorkloadGuard} {
		if len(validation.IsDNS1123Subdomain(n)) != 0 {
			return nil, cfg.ErrInvalid
		}
	}
	for _, account := range []string{p.WriterAccount, p.ProbeAccount} {
		if len(validation.IsDNS1123Subdomain(p.Name+"-"+account)) != 0 {
			return nil, cfg.ErrInvalid
		}
	}
	for _, names := range [][]string{{p.Configuration, p.Witness, p.FleetSource}, {p.WitnessGuard, p.FleetGuard, p.WorkloadGuard}} {
		seen := map[string]bool{}
		for _, n := range names {
			if seen[n] {
				return nil, cfg.ErrInvalid
			}
			seen[n] = true
		}
	}
	parts := strings.Split(p.Image, "@sha256:")
	if len(parts) != 2 || !hubWorkerImageRepository.MatchString(parts[0]) || len(parts[0]) > 384 || len(parts[1]) != 64 {
		return nil, cfg.ErrInvalid
	}
	if _, err := hex.DecodeString(parts[1]); err != nil || strings.ToLower(parts[1]) != parts[1] {
		return nil, cfg.ErrInvalid
	}
	if p.RegistryAuthentication != "" && p.RegistryAuthentication != contracts.InitialRegistryAuthentication {
		return nil, cfg.ErrInvalid
	}
	files := []core.KeyToPath{}
	for _, n := range []string{"sql-prepare.json", "sql-audit.json", "sql-activate.json", "audit-storage.json", "audit-wrap.token", "audit-unwrap.token", "kube-probe.token"} {
		files = append(files, core.KeyToPath{Key: n, Path: n})
	}
	projections := []core.VolumeProjection{
		{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: p.Configuration}, Items: []core.KeyToPath{{Key: "deployment.json", Path: "deployment.json"}}, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: p.Credentials}, Items: files, Optional: ptr.To(false)}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "kube-writer.token", Audience: p.WriterAudience, ExpirationSeconds: ptr.To(int64(600))}},
	}
	pod := &core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: p.Name, Namespace: p.Namespace, Labels: map[string]string{"app.kubernetes.io/name": "asservat", "asservat.io/private-role": "initial-installer"}}, Spec: core.PodSpec{
		RestartPolicy: core.RestartPolicyNever, ActiveDeadlineSeconds: ptr.To(int64(120)), SchedulingGates: []core.PodSchedulingGate{{Name: InitialInstallerSchedulingGate}}, EnableServiceLinks: ptr.To(false), ServiceAccountName: p.WriterAccount, AutomountServiceAccountToken: ptr.To(false), TerminationGracePeriodSeconds: ptr.To(int64(10)),
		SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
		Containers:      []core.Container{{Name: "installer", Image: p.Image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/asservat", "initial-install"}, SecurityContext: &core.SecurityContext{ReadOnlyRootFilesystem: ptr.To(true), AllowPrivilegeEscalation: ptr.To(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}, Resources: core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("64Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("500m"), core.ResourceMemory: resource.MustParse("256Mi")}}, VolumeMounts: []core.VolumeMount{{Name: "inputs", MountPath: contracts.InitialInstallerRoot, ReadOnly: true}}}},
		Volumes:         []core.Volume{{Name: "inputs", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: projections}}}},
	}}
	if p.RegistryAuthentication == contracts.InitialRegistryAuthentication {
		pod.Spec.ImagePullSecrets = []core.LocalObjectReference{{Name: p.Credentials}}
	}
	out := &InitialInstallerWorkload{Pod: pod}
	for _, name := range []string{p.WriterAccount, p.ProbeAccount} {
		out.Accounts = append(out.Accounts, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: p.Namespace}, AutomountServiceAccountToken: ptr.To(false)})
		rules := []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{p.Configuration, p.Witness, p.FleetSource}, Verbs: []string{"get"}}}
		if name == p.WriterAccount {
			rules = append(rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{p.WriterAccount, p.ProbeAccount}, Verbs: []string{"get"}})
			rules = append(rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{p.Witness}, Verbs: []string{"update"}}, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{p.Name}, Verbs: []string{"get"}})
		} else {
			rules = append(rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{p.Configuration, p.Witness, p.FleetSource}, Verbs: []string{"update"}})
		}
		out.Roles = append(out.Roles, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: p.Name + "-" + name, Namespace: p.Namespace}, Rules: rules})
		out.Bindings = append(out.Bindings, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: p.Name + "-" + name, Namespace: p.Namespace}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: p.Namespace, Name: name}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: p.Name + "-" + name}})
	}
	clusterName := "asservat." + p.Namespace + "." + p.Name
	out.ClusterRole = &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: clusterName}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{p.Namespace}, Verbs: []string{"get"}},
		{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{p.WitnessGuard, p.FleetGuard, p.WorkloadGuard}, Verbs: []string{"get"}},
	}}
	out.ClusterBinding = &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: clusterName}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: p.Namespace, Name: p.WriterAccount}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: clusterName}}
	return out, nil
}
