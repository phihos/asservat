package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type installedRecordingHTTPStatusKey struct{}

// Observe the numeric response for this one call. This transport never repeats
// HTTP requests; the SDK keeps its existing MaxRetries=-1 configuration.
type installedRecordingHTTPStatus struct{ inner http.RoundTripper }

func (s installedRecordingHTTPStatus) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := s.inner.RoundTrip(r)
	if status, ok := r.Context().Value(installedRecordingHTTPStatusKey{}).(*atomic.Int32); ok && r.Method == http.MethodPost && err == nil && response != nil {
		status.CompareAndSwap(0, int32(response.StatusCode))
	}
	return response, err
}

type installedRecordingCallError struct {
	status int
	err    error
}

func (e *installedRecordingCallError) Error() string {
	return fmt.Sprintf("MCP HTTP status=%d: %v", e.status, e.err)
}
func (e *installedRecordingCallError) Unwrap() error { return e.err }

func installedRecordingCallTool(ctx context.Context, session *sdk.ClientSession, name string, args any) (*sdk.CallToolResult, error) {
	call, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var status atomic.Int32
	if name == "get_capture" {
		call = context.WithValue(call, installedRecordingHTTPStatusKey{}, &status)
	}
	result, err := session.CallTool(call, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return nil, &installedRecordingCallError{status: int(status.Load()), err: err}
	}
	return result, nil
}

type installedRecordingInvoke func(context.Context, string, any) (installedJourneyEnvelope, string, error)

// Keep the existing four-attempt read budget and two-second pauses. Acquisition
// and mutation invocations never enter this read helper.
func installedRecordingRead(ctx context.Context, name string, args, out any, invoke installedRecordingInvoke, pause func(context.Context, time.Duration) error, logf func(string, ...any)) error {
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		began := time.Now()
		reply, code, err := invoke(ctx, name, args)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			var callError *installedRecordingCallError
			if name != "get_capture" || ctx.Err() != nil || !errors.As(err, &callError) || callError.status != http.StatusServiceUnavailable {
				return err
			}
			logf("passive get_capture HTTP503: attempt=%d/4 elapsed=%s; same original capture, no acquisition replay", attempt+1, time.Since(began))
			if attempt == 3 {
				return fmt.Errorf("get_capture HTTP503 exhausted existing four-attempt read budget: %w", err)
			}
		} else if code == "" && reply.Status == "ok" {
			return json.Unmarshal(reply.Data, out)
		} else if !installedApprovedRecordingCanRetry(reply, code) || attempt == 3 {
			return fmt.Errorf("recording read %s status=%s code=%s exhausted/refused", name, reply.Status, code)
		}
		if err := pause(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	panic("unreachable recording read budget")
}
