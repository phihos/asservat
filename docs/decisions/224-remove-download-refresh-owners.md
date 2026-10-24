# ADR-224 — Remove download-owned browser refresh

Date: 2026-10-24. Status: implemented; real SQL and installed qualification pending.
Supersedes [ADR-114](114-download-owned-browser-refresh.md).
Related: [ADR-113](113-large-native-response-accounting.md),
[ADR-119](119-public-context-download-and-prepaid-stop.md),
[ADR-060](060-bounded-browser-sessions.md).

## Problem

ADR-114 let the browser Download/prepare POST admit a server-side refresh owner
so a long native download could outlive the console tab's refresh timer. The
mechanism was agent-authored, not a maintainer requirement. The
[complexity review](../reviews/complexity-2026-10-20/adr-096-164.md) rated it
"simplify". It cost about 2,900 lines, three SQL runtime logins
(`refresh-admit`, `refresh-owner`, `refresh-read`), two tables with SECURITY
DEFINER triggers and a busy function (migration 00043), one goroutine and
Keycloak refresh schedule per owned session, and at least six failure states.
In installed runs the browser `prepare_artifact_download` returned 503 when
owner admission failed. MCP prepared the same download without an owner.

## Decision

1. The browser prepare POST is the same audited operation call as MCP's. It
   admits no owner and has no attachment callback.
2. The cookie-authenticated content GET reads the current browser session the
   way other reads do (`NewBrowserLiveReader`). It never refreshes the session,
   either in the background or inline. If the session, token or group freshness
   is no longer current, the GET fails closed: a bounded problem response
   before any bytes, or an aborted connection once bytes have been sent.
3. A session that is only busy, because another request (normally the open
   console tab) is refreshing it, is not stale. Between delivery leases, with
   no output, the response retries the identity read every 100 ms for at most
   two seconds and never past the original deadline, then fails closed. It
   refreshes nothing.
4. The console resumes with `Range` after its own explicit POST refresh, the
   same as after any interrupted transfer, within the original transfer, grant
   and session deadlines.
5. Migration 00078 drops `browser_refresh_owner`, `browser_refresh_consumer`,
   their guard functions and `browser_owned_refresh_busy`. The browser-session
   capacity trigger stays, and now counts only browser sessions. The three
   refresh role purposes are removed from the public runtime role plan.

Every existing authorization, CSRF, origin, session-expiry, ordinary one-use
refresh claim and download-deadline check is unchanged.

## Limitation

A long browser download whose console tab is closed or frozen stops when the
session next needs refreshing (the earliest of access-token expiry and the
accepted group age). Reopening the console refreshes the session, and resuming
the download continues it from the delivered offset. Native OAuth clients
already work this way with their own tokens.

## Complexity gate

1. Observed problem: page suspension during long attachments; frequency
   unmeasured. The mechanism itself caused observed 503s on prepare.
2. Accepted risk: the maintainer accepts relaxed download permission timing;
   resume after interruption is an existing workflow.
3. Typical deployments: unchanged for MCP/native clients; browser downloads
   shorter than the token/group interval are unaffected.
4. Precedent: BFF session cookies normally expire with the session; resumable
   downloads are the ordinary recovery.
5. Privileges: removes three SQL logins and per-session provider refreshes.
6. Failure states: removes about six; adds none beyond the existing
   interrupted-transfer state.
7. Configuration: none added.
8. External coupling: removes background Keycloak refresh timing.
9. Cost: removes per-session goroutines, SQL demand checks and provider calls.
10. Upgrade/rollback: forward-only migration; existing owner rows held no
    authority and are discarded.
11. Smaller fix: this is the smaller fix.
