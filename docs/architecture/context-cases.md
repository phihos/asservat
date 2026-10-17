# Ordinary context cases

C-16 now composes the first approved pod-status case metadata path under
REQ-EVD-004, REQ-MCP-005 and S-02. This is a bounded internal service and C-09
navigation adapter. It does not enable a public route, native-download runtime,
raw/share access or the complete first-release case/history model.

## Current read

`catalog.ContextCaseService.GetContextCase(ctx, CurrentIdentity, caseID)` accepts
only a request-owned identity from the existing browser/bearer ingress. It reads
current recovery for its pinned installation, then asks a separate SQL facet for
at most 100 private published-artifact locators. The caller cannot provide a
namespace, target, retained audience or storage object reference. Unknown,
unreadable, oversized and unavailable cases return the same `case unavailable`
error; hidden artifact counts and routing facts do not enter a public result.

The service checks C-03 `ScopeEligibility(ReadApproved)` for each exact historical
whole-pod target before requesting that artifact's verified catalog metadata.
It then reuses `ContextDownloadEvidence`, C-03 `Evaluate(ReadApproved)` and the
C-15 retained-policy resolver. Current complete denies, an original audience
assignment, the original classification/purpose/anchor, every retained policy
origin and the current effective expiry remain binding. Ordinary scope alone,
being the requester, publication or becoming a new workload owner is insufficient.
The service neither requires download scope to inspect ordinary metadata nor
uses an ordinary lookup as fallback for raw/shared evidence.

Only the existing fixed, independently verified pod-status metadata profile is
supported. Each returned artifact contains its opaque artifact/capture IDs,
internal target, immutable artifact version and effective access/delete dates.
There are no native hashes, filenames, byte counts, storage URLs, evidence or
free-text titles. The result can map to `Ready`, `ordinary`, `pod-status`,
`metadata`, `complete` and an empty timeline. It makes no claim about application
health or a broader incident-context recipe. The protected manifest may contain
personal identifiers, network addresses and paths, so its handling notice remains
`potentialPersonalData`; managed deletion cannot recall external copies.

The existing canonical descriptor `digest` had only a 64-hex constraint. Its
clarified meaning is the immutable verified artifact **version**, not the native
file checksum. For this profile it is the existing SHA-256 of the versioned
ciphertext-copy receipt serialization (`ContextCopiesDigest` / catalog
`CopiesDigest`). This does not introduce a new digest algorithm or RFC 8785
canonicalization. Native SHA-256 and filenames are obtained only through charged,
independently authorized native preparation; no such work occurs in `get_case`.

Current identity, unchanged permission revision and retained audience are
rechecked after blocking catalog/privacy reads. Recovery is checked again, then
identity is checked once more after final permission/recovery I/O. Every original
identity, route, deny, catalog, retained-policy, recovery, request and access
cutoff bounds the result's `ValidUntil`; later observations cannot renew it. The
transport must preserve that internal cutoff through serialization/delivery.
As elsewhere, five-second observations are bounded freshness, not a claim of
instantaneous cross-service revocation. No live Pod, Node or collector is needed
to read already published retained evidence.

## Indexed publication projection

Migration 00038 adds `context_case_locator`. It has one immutable row per
published artifact/capture, with root/case/cluster UUIDs and bounded namespace,
workload and Pod UIDs. An index on `(root_id,case_id,artifact_id)` supports exact
case lookup; the query fetches at most 101 rows and rejects overflow rather than
returning a misleading truncated case. Deleting/expired artifacts are excluded.

A fixed-source `AFTER INSERT` catalog trigger derives the locator from the
immutable accepted expectation in the same publication transaction. A separate
backfill uses existing catalog membership only. The trigger has a pinned search
path and no PUBLIC execution privilege; runtime publishers and readers cannot
supply arbitrary locator rows. Captures awaiting audit, generic ciphertext
receipts and unverified uploads do not become cases. The ordinary service still
requires the stronger existing verified catalog projection after eligibility.

The dedicated `context_case_read_runtime` credential can read routing columns
and lock current recovery. It cannot read accepted expectation JSON, change
capture/catalog/locator state or run the privileged projection function. The
existing SELECT-only catalog and current permission/retention readers retain
separate credentials. Runtime SQL credentials and fixture passwords are not a
production installation provisioner.

The table has NO ACTION foreign keys and rejects UPDATE/DELETE. This adds one
fixed bounded projection to each existing charged capture slot; it invents no
retirement or quota refund. Safe metadata retirement must remove this association
through its future purpose-owned protocol along with all dependent history.
Case grouping, aliases, editable/encrypted titles, independent case-retention
presentation, pagination/search and sharing remain separate work. No artifact is
made readable merely to keep a case visible after evidence expiry.

## Capture navigation

C-09 `ContextCaseNavigator` implements its existing `ContextCaseNavigation` port
through a consumer-owned case reader interface. It adds a link only for published
Succeeded progress and when the independent ordinary case read contains that
exact candidate artifact, capture and whole-pod target. The link retains the
minimum progress/case deadline. Failure omits navigation without converting
otherwise readable collection progress into evidence access. C-09 does not
import the C-16 application implementation or duplicate the policy evaluator.

## Qualification and remaining composition

Focused race tests cover ordinary readers, original audience membership,
permission-before-catalog ordering, exact lineage, stale/contrary final rights,
retention shortening/no extension, missing proofs, original deadline expiry,
request-owner cancellation with a background consumer context, and exact
navigation. The new integration case extends the existing real SQL/S3 publication
fixture: unpublished absence, immutable trigger projection, read-role denial,
ordinary multi-owner access, current metadata/navigation, replay uniqueness,
recovery-lock expiry, source suspension and deletion-state filtering. Its compile
check alone is not provider qualification. The subsequently integrated
[full SQL/S3 run](../../test/results/context-case-custody-final-environment.json)
passed the ordinary-case fixture with 283 total named parent/subtest entries,
831 unchanged source hashes and no cleanup failures. Earlier combined timeout
and load-sensitive failures remain recorded in implementation progress.

Production composition must supply current installation recovery, accepted
permissions and retained-policy readers, dedicated SQL credentials, public
get_case presentation and final delivery fencing. REQ-AUT-005 also requires
append-only encrypted operation intent/outcome (including denials) and outcome
acknowledgement before outward disclosure; this internal read composition does
not replace that public operation audit boundary. No fake/no-op audit adapter
may enable a route. The adjacent console/browser/MCP
work consumes this service through the same narrow port. Native download remains
separately authorized and charged; this metadata slice does not implement or
advertise a working transfer.
