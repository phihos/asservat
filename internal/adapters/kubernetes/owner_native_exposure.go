package kubernetes

import (
	"context"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
)

// OwnerNativeServiceName is the owner's external L4 Service for its native
// port (ADR-196 decision 5).
func OwnerNativeServiceName(installation string) string {
	return "asservat-" + strings.ReplaceAll(installation, "-", "") + "-owner-native"
}

// EnsureOwnerNativeService creates the owner's L4 Service on the native port
// and the ADR-197 v2 operation port,
// selecting the owner Deployment's Pods, or reopens it when its type,
// selector and port are unchanged. The server-name router on that port keeps
// connector, observation and bootstrap traffic apart (ADR-190 step 6).
func EnsureOwnerNativeService(ctx context.Context, config *rest.Config, namespace, installation, deployment, serviceTypeName string, nodePort, operationNodePort int32) error {
	serviceType := core.ServiceType(serviceTypeName)
	if ctx == nil || config == nil || namespace == "" || deployment == "" || !authorization.UUID(installation) || (serviceType != core.ServiceTypeNodePort && serviceType != core.ServiceTypeLoadBalancer) ||
		nodePort != 0 && (serviceType != core.ServiceTypeNodePort || nodePort < 30000 || nodePort > 32767) ||
		operationNodePort != 0 && (serviceType != core.ServiceTypeNodePort || operationNodePort < 30000 || operationNodePort > 32767 || operationNodePort == nodePort) {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	d, err := api.AppsV1().Deployments(namespace).Get(call, deployment, meta.GetOptions{})
	if err != nil || d.Spec.Selector == nil || len(d.Spec.Selector.MatchLabels) == 0 || len(d.Spec.Selector.MatchExpressions) != 0 {
		return cfg.ErrUnavailable
	}
	want := core.ServiceSpec{Type: serviceType, Selector: d.Spec.Selector.MatchLabels,
		Ports: []core.ServicePort{{Name: "native", Port: contracts.OwnerInstalledNativePort, TargetPort: intstr.FromInt32(contracts.OwnerInstalledNativePort), NodePort: nodePort, Protocol: core.ProtocolTCP},
			{Name: "operation", Port: contracts.OwnerInstalledOperationPort, TargetPort: intstr.FromInt32(contracts.OwnerInstalledOperationPort), NodePort: operationNodePort, Protocol: core.ProtocolTCP}}}
	services := api.CoreV1().Services(namespace)
	s, err := services.Create(call, &core.Service{ObjectMeta: meta.ObjectMeta{Name: OwnerNativeServiceName(installation)}, Spec: want}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		s, err = services.Get(call, OwnerNativeServiceName(installation), meta.GetOptions{})
	}
	if err != nil || len(s.Spec.Ports) != len(want.Ports) {
		return cfg.ErrUnavailable
	}
	if s.Spec.Type != serviceType || !equalJSON(s.Spec.Selector, want.Selector) {
		return cfg.ErrChanged
	}
	for i, w := range want.Ports {
		p := s.Spec.Ports[i]
		if p.Name != w.Name || p.Port != w.Port || p.TargetPort != w.TargetPort || p.Protocol != core.ProtocolTCP || w.NodePort != 0 && p.NodePort != w.NodePort {
			return cfg.ErrChanged
		}
	}
	return nil
}

// ReadOwnerSourceConfiguration reads the accepted owner pool configuration
// from the exact original owner source, for the regional offer.
func ReadOwnerSourceConfiguration(ctx context.Context, config *rest.Config, namespace string, source contracts.WorkerObjectReference) (contracts.OwnerConfiguration, error) {
	var out contracts.OwnerConfiguration
	api, err := installerAPI(config)
	if err != nil || ctx == nil || namespace == "" || !authorization.UUID(source.UID) {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	cm, err := api.CoreV1().ConfigMaps(namespace).Get(call, source.Name, meta.GetOptions{})
	if err != nil || string(cm.UID) != source.UID || len(cm.Data["owner-pool.json"]) == 0 {
		return out, cfg.ErrUnavailable
	}
	if strictGuardJSON([]byte(cm.Data["owner-pool.json"]), &out) != nil {
		return out, cfg.ErrInvalid
	}
	return out, nil
}
