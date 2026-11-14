package kubernetes

import (
	"net/http"
	"os"
	"sync"
	"sync/atomic"

	"asservat.local/asservat/internal/adapters/mounts"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/flowcontrol"
)

// This is a complete loopback API model with synthetic original resource,
// role/input receipts and native denial responses. It supplies no real SQL,
// provider authority, Kubernetes admission or installed startup qualification.
// The actual product readers, fixed shared observer40/probe20 QPS clients and real clock run.
type configurationProviderRuntimeFixture struct {
	reader                        *ConfigurationWorkerProviderReader
	manifest                      contracts.ConfigurationRuntimeCredentialManifest
	mounted                       map[string][]byte
	mu                            sync.Mutex
	objects                       map[string]runtime.Object
	observer, probe               atomic.Int32
	denials                       [3]atomic.Int32
	fault                         atomic.Int32
	observerLimiter, probeLimiter flowcontrol.RateLimiter
	input                         contracts.HubWorkerDeployment
	podUID                        string
	files                         *os.Root
	tokenDirectory                string
	extra                         func(http.ResponseWriter, *http.Request) bool
}

func (f *configurationProviderRuntimeFixture) setExtra(handler func(http.ResponseWriter, *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extra = handler
}

// Like the installed bootstrap bearer transport, this reads the projected file
// for every request. The surrounding native responses remain synthetic.
type configurationWorkerFixtureBearer struct {
	next  http.RoundTripper
	files *os.Root
	name  string
}

func (t configurationWorkerFixtureBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	b, err := mounts.Read(r.Context(), t.files, t.name, 16<<10)
	defer clear(b)
	if err != nil || !contracts.ValidWorkerToken(b) {
		return nil, cfg.ErrUnavailable
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return t.next.RoundTrip(r)
}
