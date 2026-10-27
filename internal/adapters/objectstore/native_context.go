package objectstore

import (
	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"net/http"
	"time"
)

// NativeContextReader performs only regional object reads and exact-object
// remote unwrap. The authenticated hub separately creates the prepaid, audited
// legacy preparation or native-window key binding before sending its command.
// This acquisition process has no SQL write credential or wrapping root.
type NativeContextReader struct {
	store    *CustodyStore
	scope    value.KeyScope
	endpoint string
	client   *http.Client
}

var _ evidence.NativeContextRead = (*NativeContextReader)(nil)
var _ evidence.NativeArtifactOpen = (*NativeContextReader)(nil)

func NewNativeContextReader(store *CustodyStore, scope value.KeyScope, endpoint string, client *http.Client) (*NativeContextReader, error) {
	if store == nil || !scope.Valid() || scope.Purpose != "artifact" {
		return nil, artifact.ErrInvalid
	}
	check, e := kms.NewRemoteOpener(endpoint, scope, scope.InstallationID, client)
	if e != nil {
		return nil, e
	}
	check.Close()
	return &NativeContextReader{store, scope, endpoint, client}, nil
}

// ReadNativeContext reads one pod-status artifact whole.
func (r *NativeContextReader) ReadNativeContext(ctx context.Context, source evidence.NativeContextSource, o value.NativeOperation, window string, until time.Time) ([]byte, error) {
	if source.Expectation.NativeType != artifact.PodStatusArtifact {
		return nil, artifact.ErrInvalid
	}
	end, opener, e := r.opener(ctx, source, o, window, until)
	if e != nil {
		return nil, e
	}
	defer opener.Close()
	reader, e := NewContextNativeReader(r.store, opener)
	if e != nil {
		return nil, e
	}
	return reader.ReadContext(ctx, source.Expectation, source.Copies, end)
}

// OpenNativeArtifact opens one stored artifact of any other registered type
// (ADR-248) with the same exact operation key authority: the three keys are
// unwrapped once here, so the remote opener is closed before any frame read.
func (r *NativeContextReader) OpenNativeArtifact(ctx context.Context, source evidence.NativeContextSource, o value.NativeOperation, window string, until time.Time) (evidence.NativeArtifactSource, error) {
	if source.Expectation.NativeType == artifact.PodStatusArtifact {
		return nil, artifact.ErrInvalid
	}
	end, opener, e := r.opener(ctx, source, o, window, until)
	if e != nil {
		return nil, e
	}
	defer opener.Close()
	v, e := NewContextVerifier(r.store, opener)
	if e != nil {
		return nil, e
	}
	return v.OpenNative(ctx, source.Expectation, source.Copies, end)
}

func (r *NativeContextReader) opener(ctx context.Context, source evidence.NativeContextSource, o value.NativeOperation, window string, until time.Time) (time.Time, *kms.RemoteOpener, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !o.Valid() || o.Reference.InstallationID != r.scope.InstallationID || !source.Valid(o.SourceVersion) {
		return time.Time{}, nil, artifact.ErrInvalid
	}
	end, ok := ctx.Deadline()
	if !ok || end.After(time.Now().Add(5*time.Second)) || !time.Now().Before(end) || end.After(until) {
		return time.Time{}, nil, artifact.ErrDownloadExpired
	}
	authority := ""
	switch o.Kind {
	case value.NativePrepare:
		if window != "" {
			return time.Time{}, nil, artifact.ErrInvalid
		}
		authority = o.ParentID
	case value.NativeResponse:
		if !value.UUID(window) {
			return time.Time{}, nil, artifact.ErrInvalid
		}
		authority = window
	default:
		return time.Time{}, nil, artifact.ErrInvalid
	}
	opener, e := kms.NewRemoteOpener(r.endpoint, r.scope, authority, r.client)
	if e != nil {
		return time.Time{}, nil, e
	}
	return end, opener, nil
}
