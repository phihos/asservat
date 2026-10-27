# ADR-250 — Standby residency for regional work and unstarted acquisition

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-EXE-002, S-02. Refines [ADR-171](171-hub-run-context-execution.md) standby
selection and [ADR-179](179-outbound-only-first-installed-profile.md) target-query selection; complements
[ADR-134](134-explicit-capture-continuation.md) and [ADR-212](212-api-preparation-remaining-interval.md).

## Problem

Installed native suites intermittently (about one capture request in five) returned
`OutcomeUnknown` from `request_capture`, with `preview_capture` sometimes failing as retryable
`NotAvailable` or a bare 503 (`reply-expired`), recovering seconds later. Hub refusal lines showed
three forms of one cause:

- `execute/PrepareAPIExecution/effect/headroom` with the request's context still at `>=2s`
  (runs 40446978365, 40410495985): the ADR-212 one-second floor was missed although the caller
  had time;
- `PrepareAPIExecution[target@0]` (run 40455550352, after the limiting-bound diagnostic below):
  the regional target observation had already lapsed;
- `execute/Check/Eligibility` with `dispatch` reported before it (run 40455557037): the exchange
  ended during the run and cancelled it.

Each regional connector keeps one passive start exchange per hub process, resident for at most 30
seconds from its opening. The region runs every operation of a work under that exchange's
context, so its target and process observations are cut to the exchange's end, and the exchange
closes there. `Router.Attach` and `Router.Query` selected the *oldest* idle standby: the one closest
to that end. Work attached in the last seconds of a standby therefore got observations with less
than a second left, or lost its stream mid-run. A real deployment hits the same window: it depends
only on the 30-second residency and the request's arrival time, not on load.

A refused start then surfaced as `OutcomeUnknown` and a message to retry the same key, although the
capture was admitted and nothing had started; a plain same-key retry only replays the acceptance.

## Decision

1. **Select a standby that outlives the work.** Attach and Query take the idle live standby with
   the latest residency end, and only if that end is at least `standbyMargin` (3 s) after the
   work's or query's own deadline (at most 5 s). The margin covers the region's exchange starting,
   and so ending, its opening's setup before the hub registers it. No authority interval, socket
   lifetime or the 30-second residency changes.
2. **Retire an idle standby that can no longer cover work.** At residency end minus 8 s, and in a
   separate prune step that Attach and Query run before their read-only selection, and when a
   finished query releases one, the router ends an idle (not attached, not querying) standby of
   that cluster so the region opens its replacement at once (its ordinary one-second reopening).
   A query still waits within its reserve for that registration; an Attach without a qualifying
   standby is refused before any effect.
3. **Report an unstarted acquisition only for temporary unavailability.** A start refused before
   any start effect as *temporarily unavailable* — an unavailable read before the regional run,
   an unavailable read-only check, the ADR-212 headroom rollback, or a run abandoned when its
   exchange ended before it entered the one-use SQL preparation (a gate refuses any preparation
   after the attachment ended) — returns `ErrAcquisitionNotStarted`. `request_capture` projects it
   as the retryable `AcquisitionNotStarted`, naming the explicit continuation
   (`continue_acquisition: true`) with the same preview and key. A denial or revocation, expiry
   (including the start's original interval or deadline), a changed target, a conflict or an
   invalid request keeps its definite class even before any effect, and any refusal after the
   preparation was entered stays `OutcomeUnknown`/`AcquisitionUncertain`.
4. A refused preparation's diagnostic line names the earliest bound of its check interval
   (`PrepareAPIExecution[<bound>@<remaining>]`), for example `target@0` or `process@<1s`.

## Consequences

Benefit: removes the observed intermittent start failures and their possible spent preparations;
the client receives an accurate, actionable code. Cost: no new permission, request, configuration
or background task beyond one timer per standby; an idle standby is replaced about every 22
seconds instead of 30 (one extra TLS opening per region per ~22 s). A request in the reopening gap
(about one to two seconds) is refused before any effect and is retried. The installed share and
history focuses now resolve and continue a request like the journey and retry retryable previews.

## Remaining limitation and rejected alternative

The region also bounds every pre-work target answer and every work by its receiver check, which
reads the connector's cached process proof and cuts the answer and the work to that proof's
original end. A proof reused near its end still yields short answers: after decision 1, run
40461388398 recorded `PrepareAPIExecution[target@<1s]/effect/headroom` with the caller holding
seconds, and admission refusals `result/resolution-expired`. These now surface as the retryable
`AcquisitionNotStarted`, preview `NotAvailable` or a closed request, all recovered by an ordinary
retry or continuation without spent work. Replacing a cached proof that had less than 2.5 s left
(tried in 8fa6b469) moved the full proof's production into requests: all four share runs
(40465614024, 40465616722, 40465619449, 40465622240) then exceeded the request bound
(`request-expired`, starts with `start-left@0`). It was reverted. A remedy needs the proof
renewed ahead of use, outside the request, which the cache's no-background-refresh contract
excludes today; that is a separate decision.

## Qualification

Component tests: router selection/retirement (`TestRouterSelectsStandbyThatOutlivesTheWork`),
preparation gate, runner pre-effect classification, headroom refusal class and public projection.
Installed native results are recorded in [implementation progress](../implementation-progress.md).
