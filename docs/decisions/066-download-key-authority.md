# ADR-066 — Bind local unwrap to an audited download

Status: engineering refinement of ADR-065 under the authorized implementation. Date: 2026-10-10. Implements part of REQ-DEP-003 and REQ-DLD-002/003. No additional human approval or public API.

The local key service must verify current operation authority independently of a valid acquisition certificate. For the initial bounded pod-status download, use its existing prepaid, audited SQL batch as the parent. The trusted download coordinator binds the exact installation/key and acquisition peer/certificate once. The binding expires no later than the original batch, current download decision or peer certificate. Repeating the binding cannot change the peer, refill slots or extend expiry.

Migration 00022 supplies this private child record. Separate SQL roles insert bindings and consume one unwrap slot for each of data, index and manifest. Before consumption, recheck current recovery, permission, retained-source and published-artifact fences in the ordinary download lock order. Derive canonical key bindings from the independently verified catalog, never from a caller-selected artifact. Commit slot consumption before invoking crypto; failed/uncertain operations retain spend. There is no saved plaintext key or response replay cache.

The acquisition adapter creates a batch-bound remote opener after audit and the current download permit. It recovers native bytes through the existing authenticated codec and S3 reader, then releases its transport. Existing external-provider readers remain an explicitly selected alternative, with no fallback between providers. The worker rejects ambiguous dual-provider composition.

This initial implementation concerns a complete 4096-byte context reader, not arbitrary raw downloads or a key-service call per payload chunk. Large artifacts must keep a bounded authorized reader across byte-delivery batches and recheck delivery rights without reconstructing the decoder or unwrapping keys per frame. Their reader/process lifetime and scheduling require separate qualification; three wraps per prepared artifact and three unwraps per opened reader remain the format contract.

The [contract](../architecture/download-key-authority.md) separates actual SQL/TLS/S3 results from pending protected peer issuance, key lifecycle, control mediation and public workflow. Static service-role ACLs, a freely renewable unwrap token and mounting roots into acquisition are rejected alternatives.
