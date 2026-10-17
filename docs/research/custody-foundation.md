# Storage custody implementation record

Date: 2026-10-09. This continues the [artifact foundation](artifact-foundation.md) with product storage-accounting and cleanup components. It does not enable end-user collection or finish S-01/S-02. The [transaction contract](../architecture/custody-transactions.md) states the exact scope and remaining authority boundaries.

Implemented: the first goose migration and sqlc query bindings; pgx transactions for backed protected allocations, four-copy registration, immutable ciphertext receipts and deletion leases; independent S3 copy verification; bounded version/marker/multipart cleanup; and a privacy coordinator that requires confirmed writer fencing before releasing capacity. `stored_unpublished` is intentionally distinct from a verified, authorized catalog artifact. SQL outbox entries are not durable object-audit acknowledgements.

Subsequent [manifest work](manifest-foundation.md) verifies the full authenticated manifest and native document for the bounded pod-status profile before recording the same unpublished custody state. The original scenarios and limits below describe this earlier ciphertext-only facet. Their successful reports are retained as `custody-before-manifest.*`; current report paths are refreshed by later regression runs. Production authority, durable audit and publication are still unimplemented.

Dependency choices continue the selected maintained families: pgx v5.11.0, sqlc v1.31.1 and goose v3.28.0. pgx is the runtime dependency; sqlc and goose are build/migration tools, not services. Primary references: [pgxpool](https://pkg.go.dev/github.com/jackc/pgx/v5/pgxpool), [sqlc configuration](https://docs.sqlc.dev/en/latest/reference/config.html), [goose SQL annotations](https://pressly.github.io/goose/documentation/annotations/). Existing AWS SDK v2 provides the storage protocol; no bespoke S3 implementation or new broker is added.

## Verification

`make custody-integration` **passed under Go 1.27.2 with the race detector** against owned PostgreSQL 18.6 and SeaweedFS fixtures. The [log](../../test/results/custody.log) and [environment/source report](../../test/results/custody-environment.json) record actual exit 0, exact images, unchanged tested source and successful removal of owned containers, anonymous volumes, network and fixture credentials. Both goose `up` calls succeeded. The runtime role could neither create a table nor edit migration history.

All nine integration scenarios passed in the final run:

- An exhausted one-connection runtime pool returned unavailable within the five-second transaction deadline and created no charge.
- 32 requests competing for the last slot admitted exactly one; 32 duplicate registrations consumed one reservation and created exactly four copies/one event.
- Backing exhaustion rejected another allocation while preserving the existing allocation's capacity. With two workload allocations on the same pool, a full workload could not borrow the neighbor's space; the neighbor still admitted its capture obligation.
- Stale configuration revisions failed without counter leaks.
- Registration blocked on an allocation lock until expiry was rejected without charge.
- Receipt finalization blocked on a later attempt lock until expiry was rejected while retaining its existing charge.
- 16 duplicate receipt transactions produced immutable `stored_unpublished` state; conflicting receipts failed and conservative storage remained charged.
- Real S3 rereads rejected a wrong ciphertext hash, accepted exact receipts, and rejected the wrong configured store. Writer-barrier failure kept charges. Following confirmed fixture writer completion, cleanup removed current/noncurrent versions, a delete marker and uploaded multipart parts; independent inventories were empty, neighboring data survived and the reservation released once. Expired verification/finalization failed; deleted-attempt replay did not resurrect it.
- Overdue obligations blocked their allocation while another backed allocation remained usable. An old deletion fence could not refund; the current fence completed idempotently.

The stale-fence test injects trusted deletion completion to isolate the SQL facet; only the separate real-S3 scenario proves its physical inventory path. The test writer barrier is synthetic because every writer in that fixture has explicitly finished. It does not qualify a distributed production cancellation/credential barrier. The storage fixture uses synthetic administrative writes to exercise older versions/markers; it does not prove production writer IAM or admission of additional copies.

`make go-check go-architecture-check sql-check` **passed**: vet, ordinary race tests, 11-package/15-edge import ownership, and three generated files matching pinned sqlc. Additional bounded TLS tests reject denied/oversized/foreign/truncated inventories, failed deletes and surviving markers; null-version deletion uses an explicit version. Application failure tests prove no release after barrier or purge failure and cap the whole cleanup pass to its lease. [Gate log](../../test/results/custody-go-check.log).

All seven design gates **passed**: spec, architecture, design, OpenAPI, downloads, combined investigation and live-watch contracts. The specification check covers 42 schemas, 154 examples, 171 requirements/scenarios and 329 rejected invalid examples; these remain contract tests, not runtime user workflows. [Design log](../../test/results/custody-design-checks.log). `make go-vuln-check` reported zero affected code/imported packages; the existing unused OpenPGP module advisory remains blocked by the import gate. [Scan log](../../test/results/custody-vuln-check.log).

Both database and object adapters use verified TLS at their client boundary in this fixture. Private backend hops are plaintext test connections; this is not a production TLS, persistence, IAM or HA qualification. No privileged collector or host kernel setting was changed. The earlier successful run is retained as `custody-initial.*`; it predates the final lease/deadline checks and is not substituted for the final report.

The existing `make context-integration` also **passed again** after the shared S3 adapter change: two newly created Kubernetes clusters, real OpenBao role denials and encrypted S3 full/range recovery. Both native projections were 353 bytes. Its [log](../../test/results/context-storage.log) and [report](../../test/results/context-storage-environment.json) record exit 0, source unchanged during execution and complete fixture cleanup. Subsequent changes affect PostgreSQL transaction waiting and custody-only assertions; all context/KMS/object-store product sources remain unchanged from that run. These remain separate component integrations, not one authorized end-user capture workflow.

The first fixture attempt reached PostgreSQL's temporary initialization server through its Unix socket, then tried migration before the final TCP listener was ready. It failed with connection refused, and all owned resources were removed. The fixture now waits on TCP explicitly. [Failed environment report](../../test/results/custody-failure-01.json).

The first SQL-generation drift check failed because sqlc resolved an absolute schema path relative to its temporary configuration directory. The gate now copies the canonical inputs into that directory and changes only the output path; the corrected gate passed without rewriting checked-in sources.

## Remaining

Capture admission still needs current actor/client/workload authorization, accepted Kubernetes configuration and execution fences, grants and durable audit. Complete artifact publication still needs authenticated semantic manifest validation and current provenance/audience/retention decisions. Production writer credentials and the quiescence barrier, store-profile admission/IAM, all-copy accounting, large multipart acquisition, policy tightening/holds, finite metadata/backup horizons, tombstone restore and operator scheduling are unimplemented. React/MCP and authenticated native-download sessions are subsequent parts of the same context slice, not completed by storage receipts.

The new tests use synthetic opaque object bytes; they do not claim native-format or full-manifest validation. The previous OpenBao/framed/context tests retain that narrower cryptographic component evidence. Production Ceph, persistent KMS and PostgreSQL HA/PITR remain unqualified.
