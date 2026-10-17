# Ordinary context download operations

`ContextDownloadOperations` projects the existing C14 coordinator's current
ordinary views into the shared canonical browser/MCP envelope. It exposes
prepare/get and, only with its concrete Stop service, cancellation. Native
filename, length, SHA-256, ETag and coverage are one independently verified group.
Neither catalog metadata nor custody candidates supply that group. Ready,
Streaming and Interrupted require it; Completed may retain only terminal status
under current metadata authority after the transfer/cache lifetime ends.

The ordinary content route is `/api/v1/downloads/{download_id}/content`. Returning
that path is not a byte permit; I-13 independently checks the live original
reader, current SQL generation, prepaid accounting and fresh short delivery
leases. This package does not mount the byte route or construct worker authority.

Prepare/get use the exact same operation-audit owner as other investigation
operations. The server request ID used by audit is the envelope ID. The browser
strict constructor additionally requires concrete `BrowserRefreshOwners`.
Its synchronous private callback invokes Admit with the original authenticated
POST's cookie, origin, CSRF value and accepted download ID. The callback is
neither serialized nor kept by background preparation. Status and MCP have no
such callback. The owner independently rechecks current session, serving process,
accepted download and SQL43 backing; its original deadline caps the response.

Only an acknowledged explicit prepare may say `continue_preparation: true`, and
only for Preparing. The console repeats the same prepare key every two seconds
while the original transfer/session bounds remain live. Unknown outcomes stop
the automatic loop. Stop clears continuation immediately, including when its
reply is uncertain; a user can retry the original cancellation key. Page/session
cancellation stops the UI loop. These are component contracts, not evidence that
an installed native attachment survives closing the tab.

## Prepaid cancellation

A protocol-marked download INSERT atomically reserves its immutable
`download_stop` row against installation and workload-allocation backing. A
missing, expired or full backing rejects the entire download reservation, so no
session or transfer charge remains after a definite rollback. The stop row is
separate from normal and resolve audit pools. No public input provisions backing.

`ContextDownloadStopCoordinator` first resolves the current actor/client, then
asks the Stop SQL role to lock only the exact owned session and stop obligation.
It does not require evidence scopes, retained-audience/catalog reads, acquisition
retention proofs or a current Pod. It cannot cancel another principal or client.
Terminal download state fences future byte leases; existing conservative
accounting may finish without refund. Source artifacts are untouched.

The first cancellation freezes one keyed request digest, original server request
ID, actor and database timestamp. Same-key retries return that original operation;
other keys cannot reset it. AlreadyTerminal preserves the finer stored outcome.
The public receipt contains no artifact ID, native metadata or retention dates.
It says only Cancelled/AlreadyTerminal and pending/recorded/overdue audit.
The UI clears previous native state and keeps this minimal receipt at most sixty
seconds within the current page/session lifecycle, without inventing an evidence
read interval.

Creation has one thirty-second write opportunity, never renewed on replay.
At most one wrap/PUT and its verification read are attempted; an uncertain result
permits at most four exact-object read/unwrap attempts. Each provider call and
acknowledgement retains the caller's original bound. A separate bounded
reconciliation call visits at most sixteen pending records, with no live human
credentials or new cancellation decision. It may find a previously written
record after the write deadline but before the original retention cutoff. A
missed unstarted write stays overdue and charged. SQL stores no plaintext native
hash, filename or raw request.

The config role can allocate/renew fixed backing without erasing charges. The
Stop role cannot acknowledge audit or read catalog; the write-claim role cannot
cancel; the independent acknowledgement role cannot claim provider work. Native
fixture credentials are synthetic and are not installation provisioning.

## Remaining integration and qualification

The component, console and selected real-provider tests pass as recorded in
[implementation progress](../implementation-progress.md). The subsequent
[Stop lifecycle](download-stop-lifecycle.md) qualifies positive writer completion,
independent absence acknowledgement and conservative finite SQL/history retirement
under synthetic accepted policy/backing inputs. The bounded I-13 exchange also
passes exact-byte and joined-completion tests with the optional
[owner listener](native-owner-listener.md). Protected backing/profile issuance,
actual backend backup/WAL qualification, connector identities and installed public
composition remain required before runtime enablement. Numeric budget floors and
component tests do not establish a supported production backup horizon.

Normal and Stop execution have separate fixed process-local slots and principal
counts in both transports. Only schema-valid configured cancellation enters the
Stop execution lane. Authentication/parsing retains a separate bounded ingress
phase; arbitrary frontdoor saturation is still a bounded admission limitation,
not a guarantee of denial-of-service immunity. Invalid invocation handling uses
the ordinary rejection audit; unauthenticated/pre-admission failures retain the
existing bounded security-counter gap.

The reservation freezes its independently configured installation and accepted
issuer epoch. Restrictive Stop does not need acquisition/recovery authority.
Audit provider claims and acknowledgements separately lock the current
`fleet_current_trust` view before the Stop row and preserve its original short
observation after waits. A blocked or mismatched incarnation permits a pending
restriction receipt but no new audit attempt. A separately accepted normal
restart is not rejected merely because admission used an older postmaster;
restore still requires the independent reconciliation/epoch protocol.
