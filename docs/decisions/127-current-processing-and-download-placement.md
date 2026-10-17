# ADR-127: Current processing decisions and complete native placement

Status: accepted design; implementation and qualification tracked separately.

Requirements: REQ-PRV-006/007, REQ-AUT-005 and the native-download requirements in [artifact downloads](../../specs/artifact-downloads.md).

## Context

A registration's store ID or S3 signing region does not approve processing or identify every plaintext processor. A mutable configuration object's empty deny list cannot erase a previously accepted processing restriction after replacement or restore. Ordinary read rights and an approved OAuth client also do not imply permission for every processing location.

## Decision

Use two sources with different responsibilities. A closed, independently guarded installation ConfigMap permits exact clients, purposes, data classes and complete independently pinned storage/acquisition/connector/hub paths. PostgreSQL retains separately initialized completeness, exact published lineage and bounded artifact/workload-time restrictions. Missing, stale, replaced or unknown restored sources deny. Migration alone creates no allowing root and never declares existing history complete.

A current privacy operator performs explicit initialization/restrict/release decisions. Initialization requires an empty catalog both before encrypted audit and under final locks. Release names the exact restricted revision, requires current independent privacy authority and an acknowledged immutable encrypted decision. The audit records prepared/effect-unknown before the business CAS; only its recorded SQL result proves the change. Same-key recovery preserves original identity, dates and spend.

Every configured rule has prepaid release capacity before restriction. A closed `processing` audit lane and `processing-release-history/v1` qualification keep normal traffic and connector identity operations from spending it. Its stable purpose-separated rule account is distinct from the actual human audit actor. Finite uncertain attempts survive rule toggles and MAC rotation. Existing ordinary v3 audit backing cannot be assumed to cover the additional business/history writes. A separate `context-processing-history/v1` acceptance backs lineage, rules, decision rows, indexes, transaction WAL and finite backup obligations.

The ordinary case reader consumes the same processing decision as downloads. Every current SQL/native download effect requires a proof bound to the exact artifact, complete lineage, recovery epoch, processing epoch/sequence, store and entire actual installed route. Historical missing optional fields remain decodable but cannot authorize a new live effect. A derived artifact cannot avoid an ancestor restriction by taking a new ID.

Each published lineage, rule and decision freezes its original coverage and retirement dates. A backing renewal cannot extend them. Expired administrative coverage cannot remove a restriction; future matching evidence that would outlive it requires explicit reconciliation. This initial protocol denies that unsupported reconciliation rather than reviving old authority.

Only eligibility-changing decisions advance the sequence. Unrelated publication or passive rule reservation leaves existing proofs unchanged. An unrelated restriction/release may conservatively interrupt a native operation; fresh current checks may continue/resume the existing download under original deadlines, range conditions and charged budgets. No new capture or implicit preparation is introduced. An affected restriction prevents new proof and stops output within the established short lease bound.

## Consequences and limits

The initial implementation covers ordinary context evidence, with exact verified pod-status root lineage. Unsupported derivatives deny until their producer provides complete independently accepted lineage. The policy is installation configuration; it adds no end-user consent step or second ordinary authorization evaluator.

Protected configuration/backing provisioning, supported restore reconciliation, full business-history retirement and operator UI remain separate work. Retained uncertain rows remain charged; configured retirement dates alone do not establish deletion or permit capacity reuse. Broad analysis/share paths must consume the same processing gate when implemented. No public runtime is enabled by this decision. See [the concrete contract](../architecture/download-environment.md) and the implementation progress record for actual qualification.
