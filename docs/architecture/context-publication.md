# Verified context publication

Partial C-14/C-08/C-15/C-21, S-01/S-02 and TASK-03/07. Migration `00012_context_publication.sql` separates a semantic verification record and catalog association from the generic copy ledger. This is an internal coordinator; it does not enable a public route or supply production collector/result authority.

`ContextPublisher` loads the immutable, intent-audited context acceptance, obtains a current `ContextPublicationGate` decision, performs full authenticated manifest/index/native verification, and rechecks the gate after I/O. The verification transaction compares the independently accepted expectation, original reservation and exact ciphertext receipts. It records those receipts and a write-once semantic verification fact atomically. A generic `stored_unpublished` custody status cannot supply this fact.

The separate audit role writes and rereads an encrypted `context-verification/v1` record binding capture, artifact/attempt, expectation/copy/intent digests, authority revision and original deadlines. It records completed verification, not a future successful download. Only its exact immutable receipt can be acknowledged. After this I/O, another current gate decision precedes catalog insertion. A lost response reuses the same capture/artifact and original verification timestamp; no acquisition, new artifact ID, deadline extension or refund occurs.

SQL locks permission root, storage pool/allocation, attempt and capture before verification/catalog state. It checks database time after blocking locks and again after writes. The current permission root/epoch/sequence/digest, acknowledged source bootstrap, recovery suspension, finite external authority lease, storage revisions and original write/read deadlines must still cover the transition. Unknown or expired authority leaves output accounted and invisible. Historical exact audit acknowledgement remains possible after revocation without publication authority.

`ContextPublicationGate` is a mandatory separate production prerequisite: independently resolve accepted execution/result provenance, collector authority at acquisition, current fleet/restore fences and complete current privacy policy. The SQL adapter cannot establish these external facts. A fixture-created five-second value does not implement that gate, and an upload cannot select its expectation or supply `verified: true`. A pod disappearing after a legitimate snapshot must not be confused with permission to collect a replacement pod.

Separate SQL verification, audit, publication and read credentials implement narrow consumer facets, composed by `ContextPublicationFacets`. The verifier cannot create catalog rows or acknowledge audit; the publisher cannot create verification facts or alter custody deadlines; audit cannot change verification scope; the reader has SELECT only. No table holds evidence text, a native plaintext hash, raw token, encryption key or complete artifact manifest. Accepted control metadata remains under the existing content-minimized capture contract.

`RetainedAudience` reads only joined catalog/verification/accepted/custody records. It refuses missing audit, unmatched copy digests, deletion state and read expiry. The ordinary authorization evaluator checks current principal/scope/denies before this lookup and intersects the original full audience afterward. This adapter is not a disclosure permission. The legacy copy-ledger label `stored_unpublished` still means custody alone cannot establish visibility; an independently valid catalog record now establishes publication. Revocation of ownership never rewrites the original audience.

Unit/race checks cover effect ordering, failures and authority changes after verification/audit. Real SQL/S3 tests cover concurrent idempotence, exact native verification, audit failure/retry, role boundaries, immutable receipts, deletion-state hiding and expiry while blocked on locks. `make custody-integration` passed the initial transaction/composition tests (`test/results/context-publication-integration-check.log`, `custody-environment.json`: exit 0, unchanged source, empty cleanup failures). The fixture uses real SQL/S3/Tink but synthetic collector/result/retention authority, not a qualified production `ContextPublicationGate`. The strengthened regression also passed after actually recording generic ciphertext custody, proving that it cannot create a catalog entry without semantic verification. The repository Go/import/SQL/spec/architecture/design gates passed in `test/results/context-publication-gates.log` after moving serialization/digest helpers to their application owner. Production gate composition, native-download sessions, full deletion/writer barriers, finite metadata/audit retirement and the public UI/MCP path remain required.

The [final retention effect contract](retention-effects.md) now requires the complete accepted source proof inside the SQL effect transaction. Its real SQL/S3 qualification and repository gates pass; it adds no public approval or policy-source selection step.

The [current recovery fence](download-recovery.md#capture-and-publication-continuation) also gates this effect. Private composition binds the installation to its permission root; lock that recovery row before ordinary permission/storage rows and recheck the original proof after waits. A blocked or changed issuer epoch cannot admit or publish new work. Completed recovery activation remains an independent prerequisite.

## Immutable audit versions at current consumers

Current capture acceptance verifies the complete retained receipt for its explicit
legacy or capture-operation protocol. New legacy intent and verification
acknowledgements require a nonempty, non-null immutable version. Publication and
current catalog, download, key and refresh consumers validate the original
verification receipt as well as its acknowledgement flag. The existing catalog
query returns both records it already joins; two formerly redundant capture
reads use that same snapshot. This adds no provider request, relation grant or
authority interval. Original post-lock identity, privacy and recovery checks remain.

Historical progress and verification-record reconstruction retain a separate
structural path. They may describe an original durable outcome without making
unversioned history current acquisition, disclosure or capacity-release authority.
No migration invents versions or changes retained receipts. Tests model legacy
rows using fixture administration and restore exact originals; their result and
remaining qualification are recorded in implementation progress.

## Publisher process (ADR-181)

[ADR-181](../decisions/181-asynchronous-publication-verifier.md) runs this
coordinator in a dedicated asynchronous `asservat publisher` process.

- **Queue.** The process polls a bounded SQL queue of stored, unpublished API
  context captures. It publishes each through the unchanged `ContextPublisher`,
  using its own gate, verification, audit and publish logins.
- **Decryption.** Keys are unwrapped only through `ContextKeyUnwraps`. That
  authority is scoped to the stored attempt, refuses published captures, is
  bounded at twelve unwraps and is never refunded. Ciphertext comes from a
  read-only evidence credential.
- **Isolation.** hub-api holds no unwrap authority, and the key service holds
  no ciphertext.
- **Request path.** It still returns `StoredPendingVerification`; the case
  becomes visible once publication completes.
