package kubernetes

import (
	"net/http"
	"sync"
	"sync/atomic"
)

type downloadPolicyBudgetFixture struct {
	source                  *DownloadEnvironmentSource
	observer, probe, denied atomic.Int32
	mu                      sync.Mutex
	before                  func(http.ResponseWriter, *http.Request) bool
}
