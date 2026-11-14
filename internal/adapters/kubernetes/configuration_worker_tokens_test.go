package kubernetes

import (
	"io"
	"net/http"
	"sync"
)

type configurationTokenRoundTripFunc func(*http.Request) (*http.Response, error)

func (f configurationTokenRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type configurationTokenIdleTransport struct{ closed int }

func (*configurationTokenIdleTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrClosedPipe
}
func (t *configurationTokenIdleTransport) CloseIdleConnections() { t.closed++ }

type configurationTokenBlockedBody struct {
	entered, release chan struct{}
	once             sync.Once
}

func (b *configurationTokenBlockedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return copy(p, []byte("late")), io.EOF
}
func (b *configurationTokenBlockedBody) Close() error { return nil }
