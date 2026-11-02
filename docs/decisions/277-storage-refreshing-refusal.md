# ADR-277 — A request refused while storage refreshes is retryable

Date: 2026-11-02. Status: accepted (agent decision).
Requirements: specs/mcp.md request_capture outcomes, ADR-200 (refresh
demand), ADR-212/250 (unstarted acquisition).

## Context

A workload's storage binding is fresh for 30 seconds. An approved recording is
usually submitted after a review that lasts longer, so its binding has expired
and the request demands a refresh (ADR-200). A refresh took up to 3.8 s on CI,
more than the request's remaining readiness wait, and the request was refused
at `facts/storage/expired/readiness-tail`. That refusal was reported as
`OutcomeUnknown`, so a careful client resolved the request; resolution closes a
request without admission, and the approval was lost. The installed
approved-recording and manual-mixed qualifications failed this way in about a
third of runs.

## Decision

An expired storage binding (`ErrStorageBindingExpired`) on `request_capture`
is reported as `StorageRefreshing`, retryable: it is raised before admission or
by an admission transaction that rolled back, so nothing was accepted. Clients
retry the same request with the same preview and key; the demanded refresh is
usually complete by then. No interval, bound or authority check changes.

## Complexity gate

Benefit: real reviews always exceed 30 s, so every approved request could hit
this. Cost: one public failure code and its mapping; no new state or
configuration. Faster or longer-lived refreshes remain possible later.
