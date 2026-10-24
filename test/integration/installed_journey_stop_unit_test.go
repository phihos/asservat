package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func installedStopReply(t *testing.T, request, download, state, audit string) installedJourneyEnvelope {
	t.Helper()
	body, err := json.Marshal(installedJourneyStopReceipt{DownloadID: download, State: state, AuditState: audit})
	if err != nil {
		t.Fatal(err)
	}
	return installedJourneyEnvelope{RequestID: request, Status: "ok", Data: body}
}

func TestInstalledJourneyStopRetainsOriginalRequestAndAuditState(t *testing.T) {
	for _, audits := range [][2]string{{"pending", "pending"}, {"pending", "recorded"}, {"recorded", "recorded"}, {"overdue", "overdue"}} {
		t.Run(audits[0]+"-"+audits[1], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			calls := 0
			out, err := installedJourneyStopTwice(ctx, func(call context.Context, name string, args any) (installedJourneyEnvelope, error) {
				until, ok := call.Deadline()
				if call != ctx || !ok || !until.Equal(deadline) || name != "cancel_artifact_download" ||
					!reflect.DeepEqual(args, map[string]string{"download_id": "original-download", "idempotency_key": "original-key"}) || calls >= 2 {
					t.Fatal("Stop replaced its original caller, scope/key or bounded call count")
				}
				reply := installedStopReply(t, "original-request", "original-download", "Cancelled", audits[calls])
				calls++
				return reply, nil
			}, "original-download", "original-key")
			if err != nil || calls != 2 || out[0].RequestID != "original-request" || out[1].RequestID != out[0].RequestID ||
				out[0].AuditState != audits[0] || out[1].AuditState != audits[1] {
				t.Fatal("Stop observation renewed or misreported the original receipt", calls, out, err)
			}
		})
	}
}

func TestInstalledJourneyStopRejectsUnknownAndReplacementWithoutRetry(t *testing.T) {
	for _, mode := range []string{"lost-first", "error-first", "already-terminal", "different-download", "missing-request", "invalid-audit", "malformed", "lost-replay", "replacement-request", "audit-regression", "cancel-before", "cancel-first"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancel-before" {
				cancel()
			}
			calls := 0
			_, err := installedJourneyStopTwice(ctx, func(context.Context, string, any) (installedJourneyEnvelope, error) {
				calls++
				reply := installedStopReply(t, "original-request", "original-download", "Cancelled", "recorded")
				if calls == 1 {
					switch mode {
					case "lost-first":
						return installedJourneyEnvelope{}, io.ErrUnexpectedEOF
					case "error-first":
						reply.Status = "error"
					case "already-terminal":
						reply = installedStopReply(t, reply.RequestID, "original-download", "AlreadyTerminal", "recorded")
					case "different-download":
						reply = installedStopReply(t, reply.RequestID, "replacement", "Cancelled", "recorded")
					case "missing-request":
						reply.RequestID = ""
					case "invalid-audit":
						reply = installedStopReply(t, reply.RequestID, "original-download", "Cancelled", "unknown")
					case "malformed":
						reply.Data = json.RawMessage(`{"download_id":`)
					case "cancel-first":
						cancel()
					}
				} else {
					switch mode {
					case "lost-replay":
						return installedJourneyEnvelope{}, io.ErrUnexpectedEOF
					case "replacement-request":
						reply.RequestID = "replacement"
					case "audit-regression":
						reply = installedStopReply(t, reply.RequestID, "original-download", "Cancelled", "pending")
					default:
						t.Fatal("failed or canceled first Stop was retried")
					}
				}
				return reply, nil
			}, "original-download", "original-key")
			wantCalls := 1
			if mode == "cancel-before" {
				wantCalls = 0
			} else if mode == "lost-replay" || mode == "replacement-request" || mode == "audit-regression" {
				wantCalls = 2
			}
			if err == nil || calls != wantCalls {
				t.Fatal("uncertain or replaced Stop was accepted/retried", calls, err)
			}
			if strings.HasPrefix(mode, "cancel-") && !errors.Is(err, context.Canceled) {
				t.Fatal("original cancellation was lost", err)
			}
		})
	}
}

type installedStopBody struct {
	io.Reader
	closed bool
	read   int
}

func (b *installedStopBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}
func (b *installedStopBody) Close() error { b.closed = true; return nil }

func TestInstalledJourneyStoppedContentRequiresBoundedNonDisclosure(t *testing.T) {
	const problem = `{"type":"about:blank","title":"Service Unavailable","status":503}`
	for _, mode := range []string{"problem", "native-200", "native-206", "native-type", "native-body", "additional-evidence", "filename", "etag", "range", "redirect", "oversized", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			body := problem
			response := &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{"Content-Type": {"application/problem+json"}}}
			switch mode {
			case "native-200":
				response.StatusCode = http.StatusOK
			case "native-206":
				response.StatusCode = http.StatusPartialContent
			case "native-type":
				response.Header.Set("Content-Type", "application/octet-stream")
			case "native-body":
				body = `{"format":"asservat-pod-status/v1","podUID":"synthetic"}`
			case "additional-evidence":
				body = strings.TrimSuffix(problem, "}") + `,"evidence":"synthetic"}`
			case "filename":
				response.Header.Set("Content-Disposition", `attachment; filename="evidence.json"`)
			case "etag":
				response.Header.Set("ETag", `"native"`)
			case "range":
				response.Header.Set("Content-Range", "bytes 0-2/3")
			case "redirect":
				response.StatusCode = http.StatusFound
			case "oversized":
				body = problem + strings.Repeat(" ", 2048)
			case "trailing":
				body = problem + `{"evidence":"synthetic"}`
			}
			tracked := &installedStopBody{Reader: strings.NewReader(body)}
			response.Body = tracked
			err := installedJourneyStoppedContent(response)
			if (err == nil) != (mode == "problem") || !tracked.closed || tracked.read > 1025 {
				t.Fatal("stopped content accepted disclosure or failed bounded closure", err, tracked.closed, tracked.read)
			}
		})
	}
}
