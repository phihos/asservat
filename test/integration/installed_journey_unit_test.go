package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestInstalledJourneyResolvesCaptureBeforeContinuationOrReplacement(t *testing.T) {
	for _, tc := range []struct {
		name         string
		code         string
		dispositions []installedJourneyDisposition
		nextCodes    []string
		nextID       string
		resolveErr   error
		wantClosed   bool
		wantErr      bool
		wantCalls    []string
	}{
		{name: "first-request-succeeds", wantCalls: []string{"confirm"}},
		{name: "unaccepted-unknown", code: "OutcomeUnknown", dispositions: []installedJourneyDisposition{{State: "closed"}}, wantClosed: true, wantCalls: []string{"resolve"}},
		{name: "changed-review-needs-close", code: "ReviewChanged", dispositions: []installedJourneyDisposition{{State: "closed"}}, wantClosed: true, wantCalls: []string{"resolve"}},
		{name: "unavailable-needs-close", code: "NotAvailable", dispositions: []installedJourneyDisposition{{State: "closed"}}, wantClosed: true, wantCalls: []string{"resolve"}},
		{name: "lost-resolution", code: "OutcomeUnknown", resolveErr: errors.New("lost response"), wantErr: true, wantCalls: []string{"resolve"}},
		{name: "missing-disposition", code: "OutcomeUnknown", dispositions: []installedJourneyDisposition{{}}, wantErr: true, wantCalls: []string{"resolve"}},
		{name: "not-started-continues", code: "AcquisitionNotStarted", dispositions: []installedJourneyDisposition{{State: "accepted", CaptureID: "original"}}, nextCodes: []string{""}, nextID: "original", wantCalls: []string{"resolve", "observe", "pause", "continue"}},
		{name: "accepted-continues", code: "OutcomeUnknown", dispositions: []installedJourneyDisposition{{State: "accepted", CaptureID: "original"}}, nextCodes: []string{""}, nextID: "original", wantCalls: []string{"resolve", "observe", "pause", "continue"}},
		{name: "successful-continuation-cannot-change", code: "OutcomeUnknown", dispositions: []installedJourneyDisposition{{State: "accepted", CaptureID: "original"}}, nextCodes: []string{""}, nextID: "replacement", wantErr: true, wantCalls: []string{"resolve", "observe", "pause", "continue"}},
		{name: "successful-continuation-needs-capture", code: "OutcomeUnknown", dispositions: []installedJourneyDisposition{{State: "accepted", CaptureID: "original"}}, nextCodes: []string{""}, wantErr: true, wantCalls: []string{"resolve", "observe", "pause", "continue"}},
		{name: "accepted-changed-review", code: "ReviewChanged", dispositions: []installedJourneyDisposition{{State: "accepted", CaptureID: "original"}}, wantErr: true, wantCalls: []string{"resolve"}},
		{name: "spent-preparation", code: "OutcomeUnknown", dispositions: []installedJourneyDisposition{{State: "accepted", CaptureID: "original"}}, nextCodes: []string{"AcquisitionUncertain"}, wantErr: true, wantCalls: []string{"resolve", "observe", "pause", "continue"}},
		{name: "closed-acquisition", code: "OutcomeUnknown", dispositions: []installedJourneyDisposition{{State: "accepted", CaptureID: "original"}}, nextCodes: []string{"AcquisitionClosed"}, wantErr: true, wantCalls: []string{"resolve", "observe", "pause", "continue"}},
		{name: "known-acceptance-never-resolves-closed", code: "OutcomeUnknown", dispositions: []installedJourneyDisposition{{State: "accepted", CaptureID: "original"}, {State: "closed"}}, nextCodes: []string{"OutcomeUnknown", ""}, nextID: "original", wantCalls: []string{"resolve", "observe", "pause", "continue", "observe", "pause", "continue"}},
		{name: "known-acceptance-never-resolves-replacement", code: "OutcomeUnknown", dispositions: []installedJourneyDisposition{{State: "accepted", CaptureID: "original"}, {State: "accepted", CaptureID: "replacement"}}, nextCodes: []string{"OutcomeUnknown", ""}, nextID: "original", wantCalls: []string{"resolve", "observe", "pause", "continue", "observe", "pause", "continue"}},
		{name: "accepted-needs-identity", code: "OutcomeUnknown", dispositions: []installedJourneyDisposition{{State: "accepted"}}, wantErr: true, wantCalls: []string{"resolve"}},
		{name: "malformed-closure", code: "OutcomeUnknown", dispositions: []installedJourneyDisposition{{State: "closed", CaptureID: "original"}}, wantErr: true, wantCalls: []string{"resolve"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			reads, continues := 0, 0
			closed, err := installedJourneyRecoverCapture(t.Context(), tc.code, func() (installedJourneyDisposition, error) {
				calls = append(calls, "resolve")
				if tc.resolveErr != nil {
					return installedJourneyDisposition{}, tc.resolveErr
				}
				if reads == len(tc.dispositions) {
					t.Fatal("unexpected extra resolution")
				}
				out := tc.dispositions[reads]
				reads++
				return out, nil
			}, func() (string, string) {
				calls = append(calls, "continue")
				if continues == len(tc.nextCodes) {
					t.Fatal("continued without an accepted original")
				}
				out := tc.nextCodes[continues]
				continues++
				return out, tc.nextID
			}, func() error {
				calls = append(calls, "confirm")
				return nil
			}, func(context.Context, time.Duration) error {
				calls = append(calls, "pause")
				return nil
			}, func(id string) (installedJourneyCaptureProgress, error) {
				calls = append(calls, "observe")
				return installedJourneyPendingProgress(id)
			})
			if closed != tc.wantClosed || (err != nil) != tc.wantErr || !reflect.DeepEqual(calls, tc.wantCalls) {
				t.Fatalf("closed=%t err=%v calls=%v; want closed=%t error=%t calls=%v", closed, err, calls, tc.wantClosed, tc.wantErr, tc.wantCalls)
			}
		})
	}
}

func TestInstalledJourneyBoundsAcceptedContinuationAndCancellation(t *testing.T) {
	continued, resolves, observations := 0, 0, 0
	closed, err := installedJourneyRecoverCapture(t.Context(), "OutcomeUnknown", func() (installedJourneyDisposition, error) {
		resolves++
		return installedJourneyDisposition{State: "accepted", CaptureID: "original"}, nil
	}, func() (string, string) {
		continued++
		return "OutcomeUnknown", ""
	}, func() error { t.Fatal("confirmed an uncertain capture"); return nil }, func(context.Context, time.Duration) error { return nil }, func(id string) (installedJourneyCaptureProgress, error) {
		observations++
		return installedJourneyPendingProgress(id)
	})
	if closed || err == nil || continued != 4 || resolves != 1 || observations != 5 {
		t.Fatal("unbounded or replaced accepted request", closed, err, continued, resolves, observations)
	}
	ctx, cancel := context.WithCancel(t.Context())
	closed, err = installedJourneyRecoverCapture(ctx, "OutcomeUnknown", func() (installedJourneyDisposition, error) {
		cancel()
		return installedJourneyDisposition{State: "closed"}, nil
	}, func() (string, string) { t.Fatal("continued after cancellation"); return "", "" }, func() error { t.Fatal("confirmed after cancellation"); return nil }, installedJourneyPause, installedJourneyPendingProgress)
	if closed || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled resolution allowed replacement", closed, err)
	}
}

func TestInstalledJourneyCaptureConfirmationWithinTwoResolutionSlots(t *testing.T) {
	for _, tc := range []struct {
		name         string
		firstCode    string
		nextCodes    []string
		wantResolves int
		wantConfirms int
	}{
		{"immediate-success", "", nil, 1, 1},
		{"first-continuation-success", "OutcomeUnknown", []string{""}, 1, 0},
		{"second-continuation-success", "OutcomeUnknown", []string{"OutcomeUnknown", ""}, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolves, continuations, confirms := 0, 0, 0
			resolve := func() (installedJourneyDisposition, error) {
				resolves++
				if resolves > 2 {
					return installedJourneyDisposition{}, errors.New("resolution audit budget exhausted")
				}
				return installedJourneyDisposition{State: "accepted", CaptureID: "original"}, nil
			}
			closed, err := installedJourneyRecoverCapture(t.Context(), tc.firstCode, resolve, func() (string, string) {
				if continuations >= len(tc.nextCodes) {
					t.Fatal("unexpected continuation")
				}
				code := tc.nextCodes[continuations]
				continuations++
				return code, "original"
			}, func() error {
				confirms++
				disposition, err := resolve()
				if err == nil && (disposition.State != "accepted" || disposition.CaptureID != "original") {
					return errors.New("confirmation changed the accepted capture")
				}
				return err
			}, func(context.Context, time.Duration) error { return nil }, installedJourneyPendingProgress)
			if err != nil || closed || resolves != tc.wantResolves || confirms != tc.wantConfirms || continuations != len(tc.nextCodes) {
				t.Fatalf("closed=%t error=%v resolves=%d confirms=%d continuations=%d; want %d/%d/%d",
					closed, err, resolves, confirms, continuations, tc.wantResolves, tc.wantConfirms, len(tc.nextCodes))
			}
		})
	}
}

func TestInstalledJourneyClosedReviewDoesNotConfirmReplacement(t *testing.T) {
	confirms := 0
	confirm := func() error { confirms++; return nil }
	noContinue := func() (string, string) { t.Fatal("unexpected continuation"); return "", "" }
	noPause := func(context.Context, time.Duration) error { t.Fatal("unexpected pause"); return nil }
	closed, err := installedJourneyRecoverCapture(t.Context(), "OutcomeUnknown", func() (installedJourneyDisposition, error) {
		return installedJourneyDisposition{State: "closed"}, nil
	}, noContinue, confirm, noPause, installedJourneyPendingProgress)
	if !closed || err != nil || confirms != 0 {
		t.Fatal("closed review was confirmed", closed, err, confirms)
	}
	// The next review has a different preview/key. Its immediate success must
	// still confirm its own admission, regardless of the previous closure.
	closed, err = installedJourneyRecoverCapture(t.Context(), "", func() (installedJourneyDisposition, error) {
		t.Fatal("immediate success entered uncertain recovery")
		return installedJourneyDisposition{}, nil
	}, noContinue, confirm, noPause, installedJourneyPendingProgress)
	if closed || err != nil || confirms != 1 {
		t.Fatal("replacement review skipped its own confirmation", closed, err, confirms)
	}
}

func TestInstalledJourneySuccessfulContinuationStillChecksCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	closed, err := installedJourneyRecoverCapture(ctx, "OutcomeUnknown", func() (installedJourneyDisposition, error) {
		return installedJourneyDisposition{State: "accepted", CaptureID: "original"}, nil
	}, func() (string, string) {
		cancel()
		return "", "original"
	}, func() error { t.Fatal("confirmed after cancellation"); return nil }, func(context.Context, time.Duration) error { return nil }, installedJourneyPendingProgress)
	if closed || !errors.Is(err, context.Canceled) {
		t.Fatal("successful continuation ignored original cancellation", closed, err)
	}
}

func installedJourneyPendingProgress(id string) (installedJourneyCaptureProgress, error) {
	return installedJourneyCaptureProgress{CaptureID: id, Phase: "Pending"}, nil
}

func TestInstalledJourneyKnownCaptureUsesCurrentProgressWithinResolutionBudget(t *testing.T) {
	resolves, continuations, observations := 0, 0, 0
	var calls []string
	closed, err := installedJourneyRecoverCapture(t.Context(), "OutcomeUnknown", func() (installedJourneyDisposition, error) {
		calls = append(calls, "resolve")
		resolves++
		if resolves > 2 {
			return installedJourneyDisposition{}, errors.New("resolution audit budget exhausted")
		}
		return installedJourneyDisposition{State: "accepted", CaptureID: "original"}, nil
	}, func() (string, string) {
		calls = append(calls, "continue")
		continuations++
		if continuations > 2 {
			t.Fatal("continued after current progress proved acquisition had advanced")
		}
		return "OutcomeUnknown", ""
	}, func() error {
		t.Fatal("confirmed an unknown continuation as successful")
		return nil
	}, func(context.Context, time.Duration) error {
		calls = append(calls, "pause")
		return nil
	}, func(id string) (installedJourneyCaptureProgress, error) {
		calls = append(calls, "observe")
		observations++
		if id != "original" {
			t.Fatal("progress selected a replacement capture")
		}
		phase := "Pending"
		if observations == 3 {
			phase = "Finalizing"
		}
		return installedJourneyCaptureProgress{CaptureID: id, Phase: phase}, nil
	})
	if err != nil || closed || resolves != 1 || continuations != 2 || observations != 3 ||
		!reflect.DeepEqual(calls, []string{"resolve", "observe", "pause", "continue", "observe", "pause", "continue", "observe"}) {
		t.Fatal("known accepted capture spent resolution budget instead of observing current progress", closed, err, resolves, continuations, observations, calls)
	}
}

func TestInstalledJourneyKnownCaptureRequiresCurrentSameCaptureProgress(t *testing.T) {
	identityUnavailable := errors.New("current identity unavailable")
	for _, tc := range []struct {
		name, captureID, phase string
		err                    error
		wantHandoff            bool
	}{
		{"running", "original", "Running", nil, true},
		{"finalizing", "original", "Finalizing", nil, true},
		{"published", "original", "Succeeded", nil, true},
		{"different-capture", "replacement", "Finalizing", nil, false},
		{"empty-capture", "", "Succeeded", nil, false},
		{"missing-phase", "original", "", nil, false},
		{"not-a-progress-phase", "original", "Accepted", nil, false},
		{"failed", "original", "Failed", nil, false},
		{"cancelled", "original", "Cancelled", nil, false},
		{"partial", "original", "Partial", nil, false},
		{"indeterminate", "original", "Indeterminate", nil, false},
		{"read-failed-with-stale-pending", "original", "Pending", identityUnavailable, false},
		{"read-failed-with-stale-success", "original", "Succeeded", identityUnavailable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolves, observations := 0, 0
			closed, err := installedJourneyRecoverCapture(t.Context(), "OutcomeUnknown", func() (installedJourneyDisposition, error) {
				resolves++
				return installedJourneyDisposition{State: "accepted", CaptureID: "original"}, nil
			}, func() (string, string) {
				t.Fatal("progress authorized another acquisition effect")
				return "", ""
			}, func() error {
				t.Fatal("progress was treated as an acknowledged continuation")
				return nil
			}, func(context.Context, time.Duration) error {
				t.Fatal("progress caused a retry pause")
				return nil
			}, func(id string) (installedJourneyCaptureProgress, error) {
				observations++
				if id != "original" {
					t.Fatal("read selected a replacement capture")
				}
				return installedJourneyCaptureProgress{CaptureID: tc.captureID, Phase: tc.phase}, tc.err
			})
			if closed || (err == nil) != tc.wantHandoff || resolves != 1 || observations != 1 ||
				(tc.err != nil && !errors.Is(err, tc.err)) {
				t.Fatal("known receipt substituted for current same-capture progress", closed, err, resolves, observations)
			}
			// Handoff, including Finalizing, only starts the native caller's
			// unchanged terminal/publication/native-byte verification.
		})
	}
}

func TestInstalledJourneyKnownCaptureFailedObservationAfterContinuationStops(t *testing.T) {
	for _, code := range []string{"OutcomeUnknown", "AcquisitionUncertain", "AcquisitionClosed", "ReviewChanged", "NotAvailable"} {
		t.Run(code, func(t *testing.T) {
			resolves, observations, continuations := 0, 0, 0
			cause := errors.New("fresh progress authorization failed")
			closed, err := installedJourneyRecoverCapture(t.Context(), "OutcomeUnknown", func() (installedJourneyDisposition, error) {
				resolves++
				return installedJourneyDisposition{State: "accepted", CaptureID: "original"}, nil
			}, func() (string, string) {
				continuations++
				return code, ""
			}, func() error { t.Fatal("confirmed unavailable collection"); return nil },
				func(context.Context, time.Duration) error { return nil },
				func(id string) (installedJourneyCaptureProgress, error) {
					observations++
					if observations == 1 {
						return installedJourneyPendingProgress(id)
					}
					return installedJourneyCaptureProgress{CaptureID: id, Phase: "Pending"}, cause
				})
			wantObservations := 1
			if code == "OutcomeUnknown" {
				wantObservations = 2
			}
			if closed || err == nil || resolves != 1 || continuations != 1 || observations != wantObservations ||
				(code == "OutcomeUnknown" && !errors.Is(err, cause)) {
				t.Fatal("uncertain preparation or unavailable observation triggered more work", closed, err, resolves, continuations, observations)
			}
		})
	}
}

func TestInstalledJourneyKnownCaptureCancellationCannotHandoffOrContinue(t *testing.T) {
	for _, stage := range []string{"pending-read", "finalizing-read", "pause", "confirmation"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			resolves, observations, confirms := 0, 0, 0
			firstCode := "OutcomeUnknown"
			if stage == "confirmation" {
				firstCode = ""
			}
			closed, err := installedJourneyRecoverCapture(ctx, firstCode, func() (installedJourneyDisposition, error) {
				resolves++
				return installedJourneyDisposition{State: "accepted", CaptureID: "original"}, nil
			}, func() (string, string) {
				t.Fatal("continued after original cancellation")
				return "", ""
			}, func() error {
				confirms++
				cancel()
				return nil
			}, func(context.Context, time.Duration) error {
				cancel()
				return nil
			}, func(id string) (installedJourneyCaptureProgress, error) {
				observations++
				phase := "Pending"
				if stage != "pause" {
					cancel()
				}
				if stage == "finalizing-read" {
					phase = "Finalizing"
				}
				return installedJourneyCaptureProgress{CaptureID: id, Phase: phase}, nil
			})
			if closed || !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled progress or confirmation was accepted", closed, err)
			}
			if stage == "confirmation" {
				if resolves != 0 || observations != 0 || confirms != 1 {
					t.Fatal("immediate success entered uncertain recovery")
				}
			} else if resolves != 1 || observations != 1 || confirms != 0 {
				t.Fatal("cancelled recovery repeated observations or confirmation")
			}
		})
	}
}

func TestInstalledJourneyAcceptedReceiptRetainsEarliestAcknowledgement(t *testing.T) {
	first := time.Now()
	var receipt installedJourneyAcceptedReceipt
	if err := receipt.remember("original", first); err != nil {
		t.Fatal(err)
	}
	if err := receipt.remember("original", first.Add(20*time.Second)); err != nil ||
		receipt.CaptureID != "original" || !receipt.AcceptedAt.Equal(first) {
		t.Fatal("continuation moved the original acknowledgement or identity", receipt, err)
	}
	for _, badID := range []string{"", "replacement"} {
		if err := receipt.remember(badID, first.Add(time.Minute)); err == nil ||
			receipt.CaptureID != "original" || !receipt.AcceptedAt.Equal(first) {
			t.Fatal("bad receipt replaced acknowledged state", receipt, err)
		}
	}
	// Only the outer acknowledged-close path starts another review; its
	// independent receipt must not inherit a previous review's timestamp.
	receipt = installedJourneyAcceptedReceipt{}
	next := first.Add(time.Minute)
	if err := receipt.remember("new-review", next); err != nil || receipt.CaptureID != "new-review" || !receipt.AcceptedAt.Equal(next) {
		t.Fatal("new review retained a different receipt", receipt, err)
	}
}

// These tokens are deliberately unsigned synthetic scheduling inputs. Only the
// native journey exercises signature verification at the actual public server.
func installedSchedulingToken(t *testing.T, now time.Time, subject, resource string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"iss": "https://id.example.invalid/realms/test", "sub": subject, "azp": "mcp", "aud": resource, "exp": now.Add(5 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
}

func TestInstalledJourneyRefreshesOriginalIdentityBeforeTokenExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	resource := "https://app.example.invalid/mcp"
	logins, refreshes := 0, 0
	source := &installedJourneyTokenSource{issuer: "https://id.example.invalid/realms/test", resource: resource, now: func() time.Time { return now }}
	source.login = func() kcTokens {
		logins++
		return kcTokens{Access: installedSchedulingToken(t, now, "developer", resource), Refresh: "first-refresh"}
	}
	source.refresh = func(token string) kcTokens {
		refreshes++
		want := "first-refresh"
		if refreshes == 2 {
			want = "second-refresh"
		}
		if token != want {
			t.Fatal("refresh did not retain the rotating original credential", token)
		}
		return kcTokens{Access: installedSchedulingToken(t, now, "developer", resource), Refresh: "second-refresh"}
	}
	first, err := source.Token(t.Context())
	if err != nil || first == "" {
		t.Fatal("first login", err)
	}
	now = now.Add(4 * time.Minute)
	same, err := source.Token(t.Context())
	if err != nil || same != first || logins != 1 || refreshes != 0 {
		t.Fatal("unnecessary login/refresh", err)
	}
	now = now.Add(31 * time.Second)
	next, err := source.Token(t.Context())
	if err != nil || next == first || logins != 1 || refreshes != 1 {
		t.Fatal("token was not refreshed before expiry", err)
	}
	now = now.Add(5 * time.Minute)
	if _, err := source.Token(t.Context()); err != nil || refreshes != 2 {
		t.Fatal("second rotation", err)
	}
}

func TestInstalledJourneyRefusesChangedRefreshIdentityAndCancelledRequests(t *testing.T) {
	for _, change := range []string{"subject", "audience", "issuer", "expired", "malformed", "missing-refresh"} {
		t.Run(change, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			resource := "https://app.example.invalid/mcp"
			source := &installedJourneyTokenSource{issuer: "https://id.example.invalid/realms/test", resource: resource, now: func() time.Time { return now },
				login: func() kcTokens {
					return kcTokens{Access: installedSchedulingToken(t, now, "developer", resource), Refresh: "original"}
				}}
			original, err := source.Token(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(5 * time.Minute)
			source.refresh = func(string) kcTokens {
				next := kcTokens{Access: installedSchedulingToken(t, now, "developer", resource), Refresh: "rotated"}
				switch change {
				case "subject":
					next.Access = installedSchedulingToken(t, now, "replacement", resource)
				case "audience":
					next.Access = installedSchedulingToken(t, now, "developer", "https://other.invalid/mcp")
				case "issuer":
					source.issuer = "https://other.invalid/realm"
				case "expired":
					next.Access = original
				case "malformed":
					next.Access = "not-a-token"
				case "missing-refresh":
					next.Refresh = ""
				}
				return next
			}
			if token, err := source.Token(t.Context()); err == nil || token != "" {
				t.Fatal("invalid identity supplied to HTTP", change)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	source := &installedJourneyTokenSource{login: func() kcTokens { t.Fatal("cancelled request logged in"); return kcTokens{} }}
	if _, err := source.Token(ctx); err != context.Canceled {
		t.Fatal("lost cancellation", err)
	}
	if err := installedJourneyPause(ctx, time.Hour); err != context.Canceled {
		t.Fatal("sleep ignored cancellation", err)
	}
}

func TestInstalledJourneyChecksCompleteWireFailureAndNeverRetainsMetadata(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"schema_version":"mcp-result/v1","request_id":"00000000-0000-4000-8000-000000000001","data_class":"metadata","status":"error","data":{"code":"NotAvailable","message":"Unavailable","retryable":true},"truncated":false,"next_cursor":null,"narrowing_hint":null,"warnings":[],"provenance":[]}`
	for _, name := range []string{"get_case", "prepare_artifact_download"} {
		reply := &sdk.CallToolResult{StructuredContent: json.RawMessage(raw), IsError: true}
		if got, err := installedJourneyReply(wire, name, reply); err != nil || got.Status != "error" {
			t.Fatal("valid refusal", name, err)
		}
		for _, broken := range []string{`{"status":"error"}`, strings.Replace(raw, "NotAvailable", "InvalidInput", 1), strings.Replace(raw, `"retryable":true`, `"retryable":"true"`, 1)} {
			reply.StructuredContent = json.RawMessage(broken)
			if _, err := installedJourneyReply(wire, name, reply); err == nil {
				t.Fatal("malformed failure counted as authority refusal", name)
			}
		}
		reply.StructuredContent, reply.IsError = json.RawMessage(raw), false
		if _, err := installedJourneyReply(wire, name, reply); err == nil {
			t.Fatal("inconsistent SDK error flag accepted")
		}
	}
	var data struct {
		State    string `json:"state"`
		Continue bool   `json:"continue_preparation"`
		SHA256   string `json:"sha256"`
	}
	if installedJourneyDecode([]byte(`{"state":"Preparing","continue_preparation":true}`), &data) != nil || !data.Continue {
		t.Fatal("acknowledged continuation missing")
	}
	if installedJourneyDecode([]byte(`{"state":"Preparing"}`), &data) != nil || data.Continue {
		t.Fatal("passive status retained continuation permission")
	}
	data.SHA256 = "old-native-digest"
	if installedJourneyDecode([]byte(`{"state":"Failed"}`), &data) != nil || data.SHA256 != "" {
		t.Fatal("terminal response retained previous native metadata")
	}
}

// Succeeded is durable capture status; its optional case link is independently
// authorized. The fixture must wait for that link without another effect.
func TestInstalledJourneyPublishedCaptureWaitsForCurrentCaseLink(t *testing.T) {
	for _, tc := range []struct {
		name      string
		progress  []string
		wantReads int
		wantReady bool
		wantErr   bool
	}{
		{name: "immediate-link", progress: []string{`{"capture_id":"original","phase":"Succeeded","case_id":"case"}`}, wantReads: 1, wantReady: true},
		{name: "published-before-current-link", progress: []string{`{"capture_id":"original","phase":"Succeeded"}`, `{"capture_id":"original","phase":"Succeeded","case_id":"case"}`}, wantReads: 2, wantReady: true},
		{name: "missing-link-stays-pending", progress: []string{`{"capture_id":"original","phase":"Succeeded"}`, `{"capture_id":"original","phase":"Succeeded"}`}, wantReads: 2},
		{name: "progress-before-current-link", progress: []string{`{"capture_id":"original","phase":"Pending"}`, `{"capture_id":"original","phase":"Running"}`, `{"capture_id":"original","phase":"Finalizing"}`, `{"capture_id":"original","phase":"Succeeded"}`, `{"capture_id":"original","phase":"Succeeded","case_id":"case"}`}, wantReads: 5, wantReady: true},
		{name: "wrong-capture", progress: []string{`{"capture_id":"replacement","phase":"Succeeded","case_id":"case"}`}, wantReads: 1, wantErr: true},
		{name: "missing-capture", progress: []string{`{"phase":"Succeeded","case_id":"case"}`}, wantReads: 1, wantErr: true},
		{name: "partial-is-failure", progress: []string{`{"capture_id":"original","phase":"Partial","case_id":"case"}`}, wantReads: 1, wantErr: true},
		{name: "failed-is-failure", progress: []string{`{"capture_id":"original","phase":"Failed","case_id":"case"}`}, wantReads: 1, wantErr: true},
		{name: "cancelled-is-failure", progress: []string{`{"capture_id":"original","phase":"Cancelled","case_id":"case"}`}, wantReads: 1, wantErr: true},
		{name: "indeterminate-is-failure", progress: []string{`{"capture_id":"original","phase":"Indeterminate","case_id":"case"}`}, wantReads: 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var progress installedJourneyCaptureProgress
			var ready bool
			var err error
			reads := 0
			for _, raw := range tc.progress {
				reads++
				if err = installedJourneyDecode([]byte(raw), &progress); err != nil {
					t.Fatal(err)
				}
				ready, err = installedJourneyCaptureCaseReady(t.Context(), "original", progress)
				if ready || err != nil {
					break
				}
			}
			if ready != tc.wantReady || (err != nil) != tc.wantErr || reads != tc.wantReads {
				t.Fatalf("ready=%t err=%v reads=%d; want ready=%t error=%t reads=%d", ready, err, reads, tc.wantReady, tc.wantErr, tc.wantReads)
			}
			if ready && progress.CaseID != "case" {
				t.Fatal("the selected case was not the current authorized link")
			}
		})
	}
}

func TestInstalledJourneyCaseLinkRequiresFreshDecode(t *testing.T) {
	progress := installedJourneyCaptureProgress{CaptureID: "original", Phase: "Succeeded", CaseID: "previously-disclosed"}
	if err := installedJourneyDecode([]byte(`{"capture_id":"original","phase":"Succeeded"}`), &progress); err != nil {
		t.Fatal(err)
	}
	ready, err := installedJourneyCaptureCaseReady(t.Context(), "original", progress)
	if err != nil || ready || progress.CaseID != "" {
		t.Fatal("omitted current navigation reused an earlier DTO or ended the wait", ready, err, progress)
	}
}

func TestInstalledJourneyCaseLinkHonorsOriginalCancellation(t *testing.T) {
	for _, name := range []string{"cancelled", "expired", "cancelled-after-read"} {
		t.Run(name, func(t *testing.T) {
			until := time.Now().Add(time.Minute)
			if name == "expired" {
				until = time.Now().Add(-time.Second)
			}
			ctx, cancel := context.WithDeadline(t.Context(), until)
			defer cancel()
			originalUntil, hasDeadline := ctx.Deadline()
			if !hasDeadline {
				t.Fatal("missing original passive deadline")
			}
			if name == "cancelled" {
				cancel()
			}
			var progress installedJourneyCaptureProgress
			if err := installedJourneyDecode([]byte(`{"capture_id":"original","phase":"Succeeded","case_id":"case"}`), &progress); err != nil {
				t.Fatal(err)
			}
			if name == "cancelled-after-read" {
				cancel()
			}
			ready, err := installedJourneyCaptureCaseReady(ctx, "original", progress)
			if ready || !errors.Is(err, ctx.Err()) || err == nil {
				t.Fatal("a cancelled original read selected a case", ready, err)
			}
			if got, ok := ctx.Deadline(); !ok || !got.Equal(originalUntil) {
				t.Fatal("the original passive deadline changed")
			}
		})
	}
}

func TestInstalledJourneyPartialRequiresExactStrongRange(t *testing.T) {
	partial := func(status int, contentRange, etag, body string) *http.Response {
		h := http.Header{}
		h.Set("Content-Range", contentRange)
		if etag != "" {
			h.Set("ETag", etag)
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}
	}
	if b, etag, err := installedJourneyPartial(partial(206, "bytes 2-4/10", `"v1-a"`, "cde"), 2, 3, 10); err != nil || string(b) != "cde" || etag != `"v1-a"` {
		t.Fatal("exact partial refused", err)
	}
	for _, r := range []*http.Response{
		partial(200, "bytes 2-4/10", `"v1-a"`, "cde"),
		partial(206, "bytes 2-5/10", `"v1-a"`, "cde"),
		partial(206, "bytes 2-4/10", `"v1-a"`, "cd"),
		partial(206, "bytes 2-4/10", `W/"v1-a"`, "cde"),
		partial(206, "bytes 2-4/10", "", "cde"),
	} {
		if _, _, err := installedJourneyPartial(r, 2, 3, 10); err == nil {
			t.Fatal("inexact partial accepted", r.StatusCode, r.Header)
		}
	}
}

func TestInstalledJourneySubmitContinuesAcceptedRefusedStart(t *testing.T) {
	var calls []string
	requests := 0
	id, err := installedJourneySubmit(t.Context(), func(name string, arguments any, data any) (string, string) {
		calls = append(calls, name)
		switch name {
		case "request_capture":
			requests++
			if requests == 1 {
				return "error", "OutcomeUnknown"
			}
			if arguments.(map[string]any)["continue_acquisition"] != true || arguments.(map[string]any)["idempotency_key"] != "key" {
				t.Fatal("continuation lost its original key", arguments)
			}
			data.(*struct {
				CaptureID string `json:"capture_id"`
			}).CaptureID = "original"
			return "ok", ""
		case "resolve_capture_request":
			*data.(*installedJourneyDisposition) = installedJourneyDisposition{State: "accepted", CaptureID: "original"}
		case "get_capture":
			*data.(*installedJourneyCaptureProgress) = installedJourneyCaptureProgress{CaptureID: "original", Phase: "Pending"}
		}
		return "ok", ""
	}, map[string]any{"preview_id": "preview", "idempotency_key": "key"})
	if err != nil || id != "original" || !reflect.DeepEqual(calls, []string{"request_capture", "resolve_capture_request", "get_capture", "request_capture"}) {
		t.Fatal(id, err, calls)
	}
	if _, err = installedJourneySubmit(t.Context(), func(name string, arguments any, data any) (string, string) {
		if name == "resolve_capture_request" {
			*data.(*installedJourneyDisposition) = installedJourneyDisposition{State: "closed"}
			return "ok", ""
		}
		return "error", "OutcomeUnknown"
	}, map[string]any{"preview_id": "preview", "idempotency_key": "key"}); err == nil {
		t.Fatal("a closed request was reported as accepted")
	}
}

func TestInstalledJourneyReviewsAgainOnlyAfterAcknowledgedClosure(t *testing.T) {
	var keys []any
	id, err := installedJourneyReviewAndSubmit(t.Context(), func(name string, arguments any, data any) (string, string) {
		switch name {
		case "request_capture":
			keys = append(keys, arguments.(map[string]any)["idempotency_key"])
			if len(keys) == 1 {
				return "error", "OutcomeUnknown"
			}
			data.(*struct {
				CaptureID string `json:"capture_id"`
			}).CaptureID = "second"
			return "ok", ""
		case "resolve_capture_request":
			*data.(*installedJourneyDisposition) = installedJourneyDisposition{State: "closed"}
		}
		return "ok", ""
	}, func(attempt int) (map[string]any, error) {
		return map[string]any{"preview_id": "preview", "idempotency_key": attempt}, nil
	})
	if err != nil || id != "second" || !reflect.DeepEqual(keys, []any{1, 2}) {
		t.Fatal(id, err, keys)
	}
}

func TestInstalledJourneyRetriesOnlyRetryableUnavailability(t *testing.T) {
	replies := []struct {
		code string
		err  error
	}{{"", errors.New("Service Unavailable")}, {"NotAvailable", nil}, {"", nil}}
	n := 0
	status, code, err := installedJourneyRetryUnavailable(t.Context(), func() (string, string, error) {
		r := replies[n]
		n++
		if r.code == "" && r.err == nil {
			return "ok", "", nil
		}
		return "error", r.code, r.err
	})
	if status != "ok" || code != "" || err != nil || n != 3 {
		t.Fatal(status, code, err, n)
	}
	n = 0
	if status, code, err = installedJourneyRetryUnavailable(t.Context(), func() (string, string, error) { n++; return "error", "UnsupportedRequest", nil }); code != "UnsupportedRequest" || err != nil || n != 1 {
		t.Fatal(status, code, err, n)
	}
}
