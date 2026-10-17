package integration

import (
	"context"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	value "asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

// This extends the owned discovery fixture before source acceptance. It checks
// actual controller port output, not installed authority, TLS or a rolling
// upgrade. Restore the original fixture Service before the legacy issuer path.
func qualifyInstalledOwnerEndpointPorts(t *testing.T, parent context.Context, admin kubernetes.Interface, client *kube.PermissionClient, original value.OwnerPool, binding value.OwnerBinding, service *core.Service) *core.Service {
	t.Helper()
	ctx, end := context.WithTimeout(parent, 15*time.Second)
	defer end()
	originalPorts := append([]core.ServicePort(nil), service.Spec.Ports...)
	service = service.DeepCopy()
	service.Spec.Ports = nil
	for _, p := range []struct {
		name   string
		number int32
	}{{"owner", 9443}, {"observation", 9444}, {"public", 9445}} {
		service.Spec.Ports = append(service.Spec.Ports, core.ServicePort{Name: p.name, Port: p.number, TargetPort: intstr.FromInt32(p.number), Protocol: core.ProtocolTCP})
	}
	var err error
	service, err = admin.CoreV1().Services(service.Namespace).Update(ctx, service, meta.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := original
	p.Port, p.NativePort, p.NativeBootstrap = 9443, 9444, value.OwnerBootstrapProfile
	reader, err := kube.NewOwnerEndpoints(client, p)
	if err != nil {
		t.Fatal(err)
	}
	wait := func(r *kube.OwnerEndpoints) {
		for {
			if result, e := r.OwnerEndpoint(ctx, binding); e == nil {
				if !result.Valid(time.Now()) || result.Binding != binding {
					t.Fatal("invalid installed discovery result")
				}
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("exact controller port graph unavailable")
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	wait(reader)
	legacy, err := kube.NewOwnerEndpoints(client, original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.OwnerEndpoint(ctx, binding); err == nil {
		t.Fatal("legacy discovery adopted installed port graph")
	}
	service.Spec.Ports = originalPorts
	service, err = admin.CoreV1().Services(service.Namespace).Update(ctx, service, meta.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wait(legacy)
	t.Log("actual installed three-port EndpointSlice accepted only by explicit profile; original legacy Service restored")
	return service
}
