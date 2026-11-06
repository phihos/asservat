package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	logcodec "asservat.local/asservat/internal/adapters/logs"
	"asservat.local/asservat/internal/domain/artifact"
)

// captureSavedLogs writes provisional native bytes; the caller may publish only
// after this function, the encoder, encryption and the current source guard all
// succeed. A changed participating instance invalidates the ENTIRE artifact.
// This function never owns a replacement target, another attempt or a deadline.
func captureSavedLogs(ctx context.Context, client *kube.SavedLogClient, pin artifact.PinnedPod, request artifact.LogCapture, anchor time.Time, dst io.Writer, now func() time.Time) error {
	if ctx == nil || client == nil || dst == nil || now == nil || !request.Valid() {
		return artifact.ErrInvalid
	}
	deadline, bounded := ctx.Deadline()
	start, end, err := request.Window(anchor)
	if !bounded || err != nil || !end.Before(deadline) {
		return artifact.ErrInvalid
	}
	if wait := end.Sub(now()); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	before, err := client.Snapshot(ctx, pin)
	if err != nil {
		return err
	}
	origins := before.Origins()
	encoder, err := logcodec.NewEncoder(ctx, dst, artifact.LogHeader{Record: "header", Format: artifact.LogFormat, PodUID: pin.UID, WindowStart: start, WindowEnd: end, Origins: uint16(len(origins))}, request.MaxNativeBytes)
	if err != nil {
		return err
	}
	for i, origin := range origins {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := encoder.BeginOrigin(origin); err != nil {
			return err
		}
		coverage := artifact.LogCoverage{Record: "coverage", OriginID: origin.OriginID, FetchOutcome: "unavailable", Gaps: []string{"rotationUnknown"}}
		if !before.Available(origin.OriginID) {
			gap := "sourceUnavailable"
			if origin.Source == "previous" {
				gap = "previousUnavailable"
			}
			coverage.Gaps = append(coverage.Gaps, gap)
		} else {
			// One fair time slice per remaining origin plus the final Pod check.
			// An unavailable source does not reserve another request or retry.
			remaining := deadline.Sub(now())
			slice := min(5*time.Second, remaining/time.Duration(len(origins)-i+1))
			if slice <= 0 {
				return context.DeadlineExceeded
			}
			fetch, cancel := context.WithTimeout(ctx, slice)
			at := now().UTC().Truncate(time.Microsecond)
			coverage.FetchStartedAt = &at
			// API LimitBytes is approximate. The adapter has a separate hard
			// local limit+1; the encoder independently bounds ENCODED bytes,
			// including empty-line-heavy expansion and all remaining metadata.
			limit := max(int64(1), request.MaxNativeBytes/int64(len(origins)))
			body, openErr := client.Open(fetch, before, origin.OriginID, start, limit)
			if openErr == nil {
				coverage.FetchOutcome = "complete"
				readErr := writeSavedLogBody(body, encoder, start, end, limit)
				closeErr := body.Close()
				if readErr != nil || closeErr != nil {
					coverage.FetchOutcome = "partial"
					switch {
					case errors.Is(readErr, artifact.ErrLimit):
						coverage.Gaps = append(coverage.Gaps, "outputFull")
					case fetch.Err() != nil:
						coverage.Gaps = append(coverage.Gaps, "timedOut")
					default:
						coverage.Gaps = append(coverage.Gaps, "sourceUnavailable")
					}
				}
			} else if fetch.Err() != nil {
				coverage.Gaps = append(coverage.Gaps, "timedOut")
			} else if origin.Source == "previous" {
				coverage.Gaps = append(coverage.Gaps, "previousUnavailable")
			} else {
				coverage.Gaps = append(coverage.Gaps, "sourceUnavailable")
			}
			finished := now().UTC().Truncate(time.Microsecond)
			coverage.FetchFinishedAt = &finished
			cancel()
		}
		if err := encoder.EndOrigin(coverage); err != nil {
			return err
		}
	}
	after, err := client.Snapshot(ctx, pin)
	if err != nil {
		return err
	}
	if !before.SameInstances(after) {
		return kube.ErrTargetChanged
	}
	return encoder.Close()
}

// A bounded prefix supplies the optional timestamp, while every retained byte
// (timestamp prefix, invalid UTF-8, NULs and newline included) is untouched.
// Long lines are fragmented; no scanner truncation or Unicode repair occurs.
func writeSavedLogBody(source io.Reader, encoder *logcodec.Encoder, start, end time.Time, limit int64) error {
	reader := bufio.NewReaderSize(io.LimitReader(source, limit+1), artifact.LogMaxFragmentBytes)
	var consumed int64
	var sourceTime *string
	newLine, include := true, true
	for {
		fragment, err := reader.ReadSlice('\n')
		if consumed+int64(len(fragment)) > limit {
			return artifact.ErrLimit
		}
		consumed += int64(len(fragment))
		if len(fragment) > 0 {
			if newLine {
				sourceTime, include = nil, true
				space := bytes.IndexByte(fragment[:min(len(fragment), 65)], ' ')
				if space > 0 {
					text := string(fragment[:space])
					if at, parseErr := time.Parse(time.RFC3339Nano, text); parseErr == nil {
						include = !at.Before(start) && !at.After(end)
						sourceTime = &text
					}
				}
			}
			if include {
				if _, writeErr := encoder.WriteLineFragment(fragment, sourceTime); writeErr != nil {
					return writeErr
				}
			}
			newLine = fragment[len(fragment)-1] == '\n'
		}
		if errors.Is(err, io.EOF) {
			if consumed >= limit {
				return artifact.ErrLimit
			}
			return nil
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return err
		}
	}
}
