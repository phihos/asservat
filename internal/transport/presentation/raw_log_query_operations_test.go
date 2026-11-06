package presentation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"slices"
)

type logBridgeRoutes struct{ *bridgeFixture }

func (f logBridgeRoutes) ResolveLogProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	c := f.a.Scope.Candidate()
	c.Logs = value.LogWindow{}
	c.RawGrantID = ""
	return c, nil
}
func rawLogBridgeFixture(t *testing.T) (*AuditedOperations, *bridgeFixture, *presentationAuditGate, []byte) {
	t.Helper()
	s, f, a, target := bridgeAuditFixture(t)
	s.Timing = func(lane, detail string) { t.Log(lane, detail) }
	f.ready = false
	source, _ := value.LookupProjectionSource(artifact.LogsArtifact)
	f.a.Scope.NativeType = source.NativeType
	f.a.Scope.SourceFormat = source.Format
	f.a.Scope.DisplayVersion = source.DisplayVersion
	f.a.Scope.SourceProjectionDigest = source.ProjectionDigest
	f.a.Scope.Selection = value.LineSelection{}
	f.a.Scope.Logs = value.LogWindow{Limit: 100}
	f.a.Scope.RawGrantID = f.next()
	f.a.Grant = value.ContextQueryGrant{ParentID: f.a.Scope.RawGrantID, ChildID: f.next()}
	f.p.Profile.Worker.MemoryBytes = value.LogQueryWorkerBytes
	f.p.Profile.Worker.WorkerTransientBytes = value.LogQueryWorkerBytes
	f.s.LogRoutes = logBridgeRoutes{f}
	f.s.Results.Ledger = newPacketBridgePort(f)
	reads, _ := f.s.RawLogQueries()
	adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err == nil {
		target.adapter, err = adapter.WithRawLogQueries(reads)
	}
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{"case_id": bridgeID, "artifact_id": bridgeID, "grant_id": f.a.Scope.RawGrantID, "idempotency_key": "original-log-page"})
	return s, f, a, input
}
func logBridgePage(f *bridgeFixture, data []byte) value.LogPage {
	o := artifact.LogOrigin{Record: "origin", ContainerKind: "regular", ContainerName: "app", Source: "current", Stream: "combined"}
	return value.LogPage{Version: f.a.Scope.Version, PodUID: f.a.Scope.PodUID, WindowStart: f.now.Add(-time.Hour), WindowEnd: f.now, Entries: []value.LogEntry{{Origin: o, Fragment: 0, Line: 1, EndLine: data[len(data)-1] == '\n', Data: base64.StdEncoding.EncodeToString(data)}}, OriginCount: 1, CompleteOrigins: 1, GappedOrigins: 1, UnknownTimestampOrigins: 1, TotalFragments: 1, SourceBytes: uint64(len(data))}
}
func TestRawLogQueryActualAuditedBeginReplayAndRawPoll(t *testing.T) {
	s, f, a, input := rawLogBridgeFixture(t)
	first, err := s.Call(t.Context(), f, "get_logs", input)
	if err != nil {
		var fixed interface{ FixedStep() string }
		stage := "unknown"
		if errors.As(err, &fixed) {
			stage = fixed.FixedStep()
		}
		t.Fatal("actual get_logs admission", err, stage)
	}
	if first.Close(context.Background()) != nil {
		t.Fatal("first closure")
	}
	replay, err := s.Call(t.Context(), f, "get_logs", input)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Close(context.Background()) != nil {
		t.Fatal("replay closure")
	}
	if f.admissions != 1 || f.starts != 1 || f.reads != 0 || len(a.outcomes) != 2 || a.outcomes[1].Effect != "none" {
		t.Fatal("replay read/debit")
	}
	f.ready = true
	p := logBridgePage(f, []byte{0xff, '\n'})
	f.result = &value.ProjectionResult{Logs: &p}
	reply, err := s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
	if err != nil {
		t.Fatal("actual logs poll", err)
	}
	defer reply.Close(context.Background())
	var out struct {
		DataClass string `json:"data_class"`
		Data      struct {
			Result struct {
				DataClass string `json:"data_class"`
				Data      struct {
					Entries []logEntryOutput `json:"entries"`
				} `json:"data"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(reply.Body, &out) != nil || out.DataClass != "raw" || out.Data.Result.DataClass != "raw" || len(out.Data.Result.Data.Entries) != 1 || out.Data.Result.Data.Entries[0].Text != nil || out.Data.Result.Data.Entries[0].BytesBase64 == nil || *out.Data.Result.Data.Entries[0].BytesBase64 != "/wo=" {
		t.Fatalf("invalidUTF8 changed or relabeled: %s", reply.Body)
	}
}

type missingLogApproval struct{}

func (missingLogApproval) Error() string                     { return "approval required" }
func (missingLogApproval) RawLogQueryApprovalRequired() bool { return true }

type logMissingAuthority struct{ *bridgeFixture }

func (logMissingAuthority) ResolveProjectionCurrent(context.Context, identities.CurrentIdentity, value.ContextProjectionCandidate) (value.ContextProjectionAuthority, error) {
	return value.ContextProjectionAuthority{}, missingLogApproval{}
}
func TestRawLogQueryApprovalRemedyBeforeEffects(t *testing.T) {
	s, f, a, input := rawLogBridgeFixture(t)
	f.s.Results.Authority = logMissingAuthority{f}
	reads, _ := f.s.RawLogQueries()
	ad, _ := NewContextProjectionOperations(f.s, f.s.Results)
	ad, _ = ad.WithRawLogQueries(reads)
	s.inner.(*projectionAuditTarget).adapter = ad
	var in map[string]any
	_ = json.Unmarshal(input, &in)
	delete(in, "grant_id")
	input, _ = json.Marshal(in)
	reply, err := s.Call(t.Context(), f, "get_logs", input)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close(context.Background())
	if !strings.Contains(string(reply.Body), `"code":"RawApprovalRequired"`) || f.admissions+f.starts+f.reads+f.batches != 0 || len(a.outcomes) != 1 || a.outcomes[0].Effect != "none" {
		t.Fatalf("lost no-effect remedy: %s", reply.Body)
	}
}
func nearFullLogBridgePage(t *testing.T, f *bridgeFixture) value.LogPage {
	t.Helper()
	data := []byte(strings.Repeat("<&\x00\"", 128))
	p := logBridgePage(f, data)
	first := p.Entries[0]
	for n := 1; n <= 100; n++ {
		trial := p
		trial.Entries = append([]value.LogEntry{}, p.Entries...)
		next := first
		next.Fragment = uint64(n)
		next.Offset = uint64(n * len(data))
		next.LineOffset = next.Offset
		next.Continuation = true
		trial.Entries = append(trial.Entries, next)
		trial.TotalFragments = uint64(len(trial.Entries))
		trial.SourceBytes = uint64(len(trial.Entries) * len(data))
		if !trial.ValidShape(f.a.Scope.Logs.Selection(f.a.Scope.CaseID, f.a.Scope.ArtifactID), f.a.Scope.Version, f.a.Scope.PodUID) {
			break
		}
		p = trial
	}
	if len(p.Entries) < 2 {
		t.Fatal("escaped fixture did not fill the bounded page")
	}
	t.Logf("bounded escaped page rows=%d", len(p.Entries))
	return p
}

func TestRawLogQueryDirectNestedEscapedOutputAndPaidInvalidClosure(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, invalid := range []bool{false, true} {
			t.Run(map[bool]string{false: "direct", true: "nested"}[nested]+map[bool]string{false: "", true: "-bad-version"}[invalid], func(t *testing.T) {
				s, f, _, input := rawLogBridgeFixture(t)
				if nested {
					initial, err := s.Call(t.Context(), f, "get_logs", input)
					if err != nil {
						t.Fatal(err)
					}
					_ = initial.Close(context.Background())
				}
				f.ready = true
				p := nearFullLogBridgePage(t, f)
				if invalid {
					p.Version = artifact.Digest{99}
				}
				f.result = &value.ProjectionResult{Logs: &p}
				name := "get_logs"
				if nested {
					name = "get_query_result"
					input = bridgePoll(f.q.ID)
				}
				reply, err := s.Call(t.Context(), f, name, input)
				if invalid {
					if len(reply.Body) > 0 {
						defer reply.Close(context.Background())
						if !strings.Contains(string(reply.Body), `"status":"error"`) {
							t.Fatal("invalid raw DTO disclosed", string(reply.Body))
						}
					} else if err == nil {
						t.Fatal("missing unavailable result")
					}
					if f.reads != 1 || f.lastRead == nil || !f.lastRead.closed {
						t.Fatal("invalid paid read not joined")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer reply.Close(context.Background())
				wire, _ := contracts.NewInvestigationContracts()
				if len(reply.Body) > contracts.InvestigationOutputLimit || wire.ValidateOutput(name, reply.Body) != nil || !strings.Contains(string(reply.Body), `\u003c`) {
					t.Fatal("escaped bounded result invalid", len(reply.Body), string(reply.Body))
				}
			})
		}
	}
}

func TestRawLogQueryKnownRefusalKeepsPaidOwnerThroughAuditAndJoin(t *testing.T) {
	for _, kind := range []string{"cursor", "size"} {
		for _, mode := range []string{"closed", "audit-failed", "join-unknown"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				s, f, a, input := rawLogBridgeFixture(t)
				f.ready = true
				f.result = &value.ProjectionResult{InvalidCursor: kind == "cursor", TooLarge: kind == "size"}
				if mode == "audit-failed" {
					a.finishFail = true
				}
				if mode == "join-unknown" {
					f.closeErr = value.ErrUnavailable
				}
				reply, err := s.Call(t.Context(), f, "get_logs", input)
				if mode == "audit-failed" {
					if err == nil || len(reply.Body) != 0 {
						t.Fatal("unaudited refusal escaped")
					}
				} else {
					if err != nil || !strings.Contains(string(reply.Body), `"status":"error"`) {
						t.Fatal("typedrefusalownerlost", err, string(reply.Body))
					}
					_ = reply.Close(context.Background())
				}
				if f.reads != 1 || f.lastRead == nil || !f.lastRead.closed {
					t.Fatal("paidrefusalnotjoined")
				}
				if len(a.outcomes) != 1 || a.outcomes[0].Effect != "accepted" || a.outcomes[0].Status != "denied" && kind == "size" || a.outcomes[0].Status != "invalid" && kind == "cursor" {
					t.Fatal("paidrefusaloutcomelost", a.outcomes)
				}
			})
		}
	}
}

func TestRawLogQueryCaptureApprovalChoicesMatchSubmission(t *testing.T) {
	plan := planning.RecorderPlan{Actions: []planning.RecorderAction{{ID: "logs", Kind: "logs"}, {ID: "meta", Kind: "packetCapture", PacketProfile: "networkHeaders"}}}
	if got := recorderResultAccessActions(plan); got != nil {
		t.Fatal("observe collection cannot carry result access without a collection review", got)
	}
	if warnings := recorderWarnings(plan); len(warnings) < 2 || !strings.Contains(warnings[1], "After collection, request separate approval") {
		t.Fatal("standalone saved-result remedy not explained", warnings)
	}
	plan.Approval = &planning.RecorderApproval{}
	got := recorderResultAccessActions(plan)
	if len(got) != 1 || got[0].ActionID != "logs" || !slices.Equal(got[0].Operations, []string{"download_artifact", "get_logs"}) {
		t.Fatal("reviewed logs must offer exact result choices", got)
	}
}
