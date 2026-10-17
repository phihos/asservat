package contextstart

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

// NewOutboundStream is the receiving half of one connector-originated HTTP/2
// POST, after the installed mTLS adapter has verified the actual hub and sent
// its hello. It accepts no destination and can never establish/retry a socket.
// The adapter's joined close function owns its one RoundTrip/pipe writer.
// source is the region's own connector source reader (ADR-178); the hub asks
// for it while the stream waits for work, and it precedes the result.
func NewOutboundStream(ctx context.Context, channel fleet.APIContextChannel, check ReceiverCheck, source app.ConnectorIdentitySourceReader, targets QueryTargets, response *http.Response, request *io.PipeWriter, connection net.Conn, joinedClose func()) (Stream, error) {
	if ctx == nil || ctx.Err() != nil || response == nil || response.Body == nil || response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.Version != tls.VersionTLS13 || response.TLS.NegotiatedProtocol != "h2" || response.ProtoMajor != 2 || response.StatusCode != http.StatusOK || response.ContentLength != -1 || len(response.TransferEncoding) != 0 || request == nil || connection == nil || joinedClose == nil {
		return nil, fleet.ErrInvalid
	}
	values := response.Header.Values("Content-Type")
	if len(values) != 1 || values[0] != contracts.APIContextStartMedia || len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Location")) != 0 {
		return nil, fleet.ErrInvalid
	}
	stream, e := newFrameStream(ctx, channel, check, response.Body, request, connection.SetReadDeadline, connection.SetWriteDeadline, func() error { return nil }, func() {
		_ = request.CloseWithError(fleet.ErrUnavailable)
		_ = connection.SetDeadline(time.Now())
		_ = connection.Close()
		_ = response.Body.Close()
		joinedClose()
	})
	if e != nil {
		return nil, e
	}
	stream.local = source
	stream.targets = targets
	// Hello and the first source frame precede this stream; charge their ceilings.
	stream.frames = 2
	stream.bytes = contracts.APIContextWorkBytes + 5 + contracts.APIContextSourceBytes + 5
	return stream, nil
}
