package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
