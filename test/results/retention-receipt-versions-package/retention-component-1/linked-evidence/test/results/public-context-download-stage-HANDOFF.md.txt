# Public ordinary context download and prepaid Stop — SQL46 / ADR119

This is a source package for guarded integration, not public runtime enablement.
The final manifest and patch identify the frozen payload; generated SQL is a
compile-only overlay and must be regenerated from combined parent SQL45/46.

## Behavior

Shared C14 prepare/get and scope-independent original-actor/client cancellation
are projected through the existing canonical browser/MCP envelope and audit
mediator. Native metadata remains one independently verified group. Status never
acquires evidence. The strict browser constructor requires concrete SQL43 refresh
ownership and supplies a synchronous callback owned by the exact authenticated
prepare POST. GET/status and MCP never acquire a browser owner or credentials.

Acknowledged Preparing may opt into finite same-key continuation, ending on
unknown results, original expiry, Stop or page/session cancellation. Stop returns
only Cancelled/AlreadyTerminal and pending/recorded/overdue audit, clearing native
metadata. It preserves the first request key/ID and never refills capacity.

SQL46 reserves one Stop obligation in the same download INSERT transaction,
before native acquisition. Missing/full/expired backing rolls back the download
reservation. Restriction commits before separate bounded encrypted audit I/O.
Only one write and four exact lookups are admitted; one immutable decision and
all original dates survive retries. Stop does not require evidence scopes, read
catalog, or change artifact custody. Terminal state fences acquisition while
historical byte accounting and conservative charges remain intact.

Normal and Stop work have separate slots/principal counts. Schema-invalid input
cannot reserve Stop execution capacity. Authentication/parsing stays bounded
separately; this is not a denial-of-service immunity or distributed priority claim.

## Verification evidence

- `final-race-after.log`: seven affected Go packages passed race tests; MCP is a
  fresh 9.765s run, the other unchanged package results were cached passes.
- `browser-lane-before.log`: new invalid-Stop classification regression failed
  against the previous staged handler (400 instead of saturated normal-lane429).
- `browser-lane-after.log`: full browser and artifact-domain race tests passed
  (4.523s / 2.935s), including the corrected classification.
- `final-vet.log`: eight affected packages, including integration source, passed.
- `ui-before.log`: meaningful minimal Stop receipt regression failed against the
  original controller. `ui-after.log` and final `final-ui.log`: three files / forty tests passed.
- `web-types-after.log` and `final-types.log`: TypeScript check passed after explicit status-union
  narrowing. `download-contracts.log`: 32 positive / 152 negative canonical DTO
  cases passed. These are synthetic contract/component results.
- SQLc and the nine embedded implemented-schema generation succeeded. Parent
  must regenerate SQL across SQL45/46, never overwrite SQL45 with this overlay.
- `integration-compile.log` and `final-combined45-compile.log`: integration
  package compiled; no external test selected or run. The real provider fixture is source only until parent runs it.

Preserved failed attempts are not qualifications: `final-race.log` is an invalid
Go flag/setup invocation; the first browser fake incorrectly equated permission
to refresh with an actual rotation; the first UI disposable tree lacked examples;
and the first TS run exposed union narrowing. The earlier full MCP run hung due
to missing protocol-method principal accounting after the refactor; its owned
process was terminated with SIGQUIT, the trace is in `focused-race.log`, and the
restored accounting plus separated business counts pass both protocol revisions.

The native fixture now checks actual missing-backing rollback, real normal audit
pool exhaustion, authenticated Stop without evidence scopes, original-key replay,
foreign-client/new-key rejection, unchanged nonzero admitted read work and active
batch identity, denial of further permission, historical joined completion,
unchanged source custody, exact SQLSTATE42501 role denials, and Stop during actual incarnation mismatch
with zero audit attempt spend. Installation and
human authority inputs remain explicitly synthetic. Additional pools close on
helper exit and the temporary normal audit pools close before cancellation.

## Merge notes

The schema head and pristine inventory were rebased onto live45, retaining its
native tables. Runtime roles append the separate Stop roles. `download.sql` adds the optional Stop
protocol insert field; regenerate all sqlc output with native SQL45 present. The
native fixture hook is one new `qualifyDownloadStop` call next to the existing
refresh-owner hook. Existing auth/session/CSRF/logout files are untouched.

Canonical full cancellation schema preserves the legacy detailed response for
compatibility; the implemented ordinary subset exposes only the minimized
receipt. Raw/grant input remains disabled in the implemented prepare subset.
New owned generated browser files are only evidence types/validator, not auth.

## Remaining work / next task

Continue migration47 / ADR124 separately using `LIFECYCLE-NEXT.md`: actual positive
joined producer completion, independent all-version absence, fixed object/SQL/
backup/WAL retirement and original charged cooling history. A recorded receipt or
successful Find never supplies writer completion. SQL46 deliberately permits no
charge release or metadata deletion; it is not a completed privacy lifecycle.
Its numeric backing minima do not qualify a production backend. General existing
download/batch/window/worker metadata also retains its separate finite cleanup
obligation. Unknown/overdue work stays charged and visible, never gains a privacy
exemption or fake completion through timeout.

Protected backing issuance, exact provider role composition, native I13/public
startup and full installed browser/MCP journeys remain parent-composed. Missing/
foreign Stop lookups do not create unlimited individual audit rows; they are
pre-admission nondisclosing failures. Fixed security counters still lack durable
persistence. No collector, native public route or Helm runtime is enabled here.

Final review also found and fixed missing audit-side recovery fencing. Stop
restriction remains independent, but original installation/issuer epoch and
current accepted incarnation now gate every provider claim/acknowledgement.
The first combined compile after parent integrated45 failed because the older
overlay omitted its generated models; the pinned SQL tool regenerated45/46 and
compilation passed. An intervening PATH-only sqlc invocation was a setup failure.
No native result is claimed from any of these compilation commands.

Final post-review evidence: `recovery-compile.log` is terminal0 for the affected
artifact/evidence/objectstore tests and Postgres/integration compilation against
combined45/46. `final-post-review-vet.log` is terminal0 for the amended Postgres,
browser and integration source. The native recovery/Stop test hook remains unrun.
All payload files are now frozen; the base hashes include current live45.
