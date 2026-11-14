package integration

// Installed qualification uses only the real public/session/source pipelines.
// Administrator SQL is read-only evidence, never an authority producer.
import (
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// Persistent driver is ready before a short finite HTTP source starts. Private
// stdin contains only original test cookies and expected source metadata.
type installedLiveBrowser struct {
	t          *testing.T
	in         io.WriteCloser
	events     chan json.RawMessage
	done       chan error
	cancel     context.CancelFunc
	cmd        *exec.Cmd
	diagnostic *consoleBoundedOutput
	once       sync.Once
}

func (p *installedLiveBrowser) send(v any) {
	p.t.Helper()
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 16<<10 {
		p.t.Fatal("bounded installed browser command")
	}
	if _, e = p.in.Write(append(raw, '\n')); e != nil {
		p.t.Fatal("browser input unavailable")
	}
	clear(raw)
}
func (p *installedLiveBrowser) read(out any) {
	p.t.Helper()
	var raw json.RawMessage
	ok := false
	select {
	case raw, ok = <-p.events:
	case <-time.After(3 * time.Minute):
		// A stuck browser script must not hold the test until the CI job limit.
	}
	if !ok || json.Unmarshal(raw, out) != nil {
		p.t.Fatal("installed browser event unavailable", p.diagnostic.String())
	}
}
