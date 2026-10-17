package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"errors"
	"testing"
	"time"
)

// Synthetic ports exercise order/fencing; these are not audit/provider or
// native-worker qualification.
type contentAuditFixture struct {
	*responseTransferFixture
	begun, finished, described, notified int
	status                               DownloadContentStatus
	end                                  time.Time
	mode                                 string
	condition                            error
}

func (f *contentAuditFixture) BeginDownloadContent(_ context.Context, _ identities.CurrentIdentity, _ DownloadResponseRequest) (DownloadContentAudit, error) {
	f.begun++
	f.end = f.now.Add(5 * time.Second)
	if f.mode == "begin-expired" {
		f.now = f.now.Add(6 * time.Second)
	}
	if f.mode == "begin-failed" {
		return nil, artifact.ErrDownloadUnavailable
	}
	return &contentAuditHandle{f}, nil
}

type contentAuditHandle struct{ f *contentAuditFixture }

func (h *contentAuditHandle) Deadline() time.Time { return h.f.end }
func (h *contentAuditHandle) Close()              {}
func (h *contentAuditHandle) Finish(_ context.Context, s DownloadContentStatus) (time.Time, error) {
	f := h.f
	f.finished++
	f.status = s
	if f.begins != 0 || f.emitted != 0 {
		return time.Time{}, errors.New("bytes reserved before preflight acknowledgement")
	}
	switch f.mode {
	case "finish-failed":
		return time.Time{}, artifact.ErrDownloadUnavailable
	case "finish-expired":
		f.now = f.now.Add(6 * time.Second)
	case "finish-revoked":
		f.fail = "authority"
	case "finish-shortened":
		f.a.AccessUntil = f.now.Add(10 * time.Second)
		f.a.DeleteBy = f.now.Add(20 * time.Second)
	}
	return f.end, nil
}
func (f *contentAuditFixture) Describe(c context.Context, s artifact.DownloadSession, a artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error) {
	f.described++
	if f.begun != 1 {
		return artifact.NativeDownloadMetadata{}, 0, errors.New("metadata before audit")
	}
	return f.responseTransferFixture.Describe(c, s, a)
}
func (f *contentAuditFixture) SelectDownloadResponse(m artifact.NativeDownloadMetadata) (artifact.DownloadSelection, error) {
	if f.condition != nil {
		return artifact.DownloadSelection{}, &DownloadContentSelectionError{DownloadContentNotModified, f.condition}
	}
	return f.responseTransferFixture.SelectDownloadResponse(m)
}
func (f *contentAuditFixture) DownloadContentPreflightComplete(time.Time) { f.notified++ }
func TestNativeContentPreflightPrecedesReservationAndConditionalDisclosure(t *testing.T) {
	for _, mode := range []string{"ready", "conditional", "begin-expired", "begin-failed", "finish-failed", "finish-expired", "finish-revoked", "finish-shortened"} {
		t.Run(mode, func(t *testing.T) {
			base, transfer, request := newResponseTransferFixture(t, 17)
			f := &contentAuditFixture{responseTransferFixture: base, mode: mode}
			sentinel := errors.New("not modified")
			if mode == "conditional" {
				f.condition = sentinel
			}
			err := transfer.TransferAudited(context.Background(), base, request, f, f, f)
			switch mode {
			case "ready", "finish-shortened":
				if err != nil || f.finished != 1 || f.notified != 1 || f.emitted != 17 || f.s.State != artifact.DownloadCompleted {
					t.Fatalf("preflight/body: %v %+v", err, f)
				}
				if mode == "finish-shortened" && f.r.Until.After(f.a.AccessUntil) {
					t.Fatal("current shortening ignored")
				}
			case "conditional":
				if !errors.Is(err, sentinel) || f.status != DownloadContentNotModified || f.finished != 1 || f.notified != 1 || f.begins != 0 || f.emitted != 0 {
					t.Fatal("conditional changed effects or skipped acknowledgement", err)
				}
			default:
				if err == nil || f.notified != 0 || f.begins != 0 || f.emitted != 0 {
					t.Fatal("failed audit disclosed/reserved", err)
				}
				if (mode == "begin-expired" || mode == "begin-failed") && f.described != 0 {
					t.Fatal("metadata after failed original intent")
				}
			}
		})
	}
}
