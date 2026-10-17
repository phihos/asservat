# Original connector permit interval overlap

Nine hash-guarded paths in `work/`; apply only after verifying `manifest.json` bases against the live tree. Frozen SQL49 package and live sources were not changed. No migration, wire field, serialization, source pin, role grant or effect deadline changes.

The first actual SQL49 fast fixture failed during initial client issuance. The archived PostgreSQL log contains no unexpected SQL error, but that alone does not identify the cause. The new persisted-permit decoder regression reproduces the exact generic error with valid sequential observations: `CheckedAt` is captured at request entry, while current Pod/source/recovery observations naturally start later. Historical validation incorrectly evaluated those observations at request entry.

`ConnectorCredentialPermit.WellFormed` validates the existing `Valid` predicate at the latest contributing original observation start. This requires a real intersection with the unchanged original signing deadline and preserves every constituent maximum interval and expiry. The persisted-result decoder, immutable attempt matching and stored X.509 result verification use that historical predicate. Signing, claims, current provider checks and delivery retain their actual current-time and independent authority checks. No request start or end is moved.

Verification, all using GOMAXPROCS=2 and -p=2 with an isolated Go overlay:

- Before: selected application coordinator, actual PostgreSQL result decoder and real X.509 verifier tests exited 1; both client/server staggered cases fail. `evidence/before.log`.
- After: complete domain/fleet, application/fleet, adapters/postgres, adapters/mtls and adapters/kms race suites exited 0. Includes cached observations, no overlap, shortened ends, oversized intervals, wrong issuer, original expiry and fresh same-key reconciliation without repeated signing. `evidence/after-race.log`.
- Five affected packages `go vet` exited 0. `evidence/vet.log`.
- `test/integration` compile with `-run '^$'` exited 0; no external test ran. `evidence/integration-compile.log`.

Parent must rerun the exact actual SQL/S3 selection `TestContextAdmissionWithRealServices/connector-identity-fast`. This remains necessary to establish whether the correction resolves the first native failure and exposes any subsequent SQL/runtime defects. The finite SQL51 retirement follow-up remains isolated and unqualified; this change neither enables connector runtime nor completes its lifecycle.

Manifest SHA256: `fb3cd11b98056d079ef23cd8783ad1942a9e9bad6832c75a9ef4bc1dc9d94a95`.
Patch SHA256: `be84efb7dcf22d396991ea982ab09d0c997ea9ff6b38e555e5a195bce697d7e1`.
