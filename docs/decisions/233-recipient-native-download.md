# ADR-233 — Recipient native download of a shared artifact (S-06 increment 3)

Date: 2026-10-26. Status: accepted; implemented; qualification below.
Requirements: REQ-SHR-001/003 (narrowed as in [ADR-232](232-concrete-evidence-share.md)), the
maintainer requirement of native download for all gathered evidence
([artifact downloads](../../specs/artifact-downloads.md)), S-06 (TASK-07). Plan: the S-06 plan
`docs/reviews/s06-plan-2026-10-26.md`, increment 3.

## Problem

After ADR-232 a recipient can read a shared pod-status artifact with `get_case`, but
`prepare_artifact_download` refuses them: the download authorizer has no share branch. The
maintainer requires native download of all gathered evidence; a recipient who may read the
metadata view but not fetch the file has to ask the owner to download and forward it, which
creates an unmanaged copy outside Asservat.

## Decision

1. **Share branch in the download authorizer, not a new authority.** `ContextDownloadAuthority`
   (C-03) gets an optional `Shares ShareReader` (the ADR-232 port, wired to the same
   `postgres.EvidenceShares`). The ordinary path is unchanged. Only when ordinary
   `ScopeEligibility(DownloadApproved)` refuses, the caller's own shares of exactly the scope's
   artifact and verified version are read **before** the catalog read; no admitting share, no
   catalog read. When the ordinary target check passes but the retained audience refuses, the
   share lookup follows the catalog read (as in ADR-232). After the catalog read the share must
   also name the artifact's case (`ContextDownloadEvidence.CaseID`, from the verified expectation).
2. **Domain.** `EvaluateShareFor(op, …)` is `EvaluateShare` for `ReadApproved` or
   `DownloadApproved`. `DownloadApproved` additionally requires the `evidence:download` scope,
   exactly as the ordinary facet does; denies whose role permits either operation win alike;
   `CollectContext`, raw classes and other artifacts stay refused.
3. **Recheck points are the ordinary path's.** The share is re-read at the authorizer's final
   check (a revocation or expiry between the first read and the decision refuses), so every
   prepare, get and new content request re-reads it. Within one content response the
   ADR-220 entitlement observation is reused for shares as for ordinary rights: a share-admitted
   entitlement is reconstructed at the existing 30-second cadence (the maintainer-authorized
   relaxed interval; no per-chunk check) and never later than the share's `expires_at`.
   Reconstruction re-reads the share, so a revoked, expired or suspended share refuses at the
   next recheck. The decision digest binds the share ID and revision.
4. **Budgets and effects unchanged.** A recipient's session is reserved against the workload's
   existing download allocation (`ContextDownloadPlan`), charged and audited exactly like an
   ordinary session; the SQL download fence (permission revision, retention, recovery, published
   version) is unchanged. No read is gated on live source-workload capacity.
5. **No new privilege.** The hub-runtime credential already holds the ADR-232 `evidence-share`
   duty (SELECT on `evidence_share`); the download gate runs in the same process. No migration,
   no new SQL grant, no Kubernetes, worker, key-service or network change.

ADR-220's sentence "no raw/share grant … inherits this observation" is amended for shares only:
a share-admitted entitlement inherits the same response-owned 30-second reconstruction, bounded
additionally by the share's expiry. Raw grants remain excluded.

## Complexity gate (AGENTS.md)

1. **Frequency/harm:** every recipient who needs the native file (the maintainer's stated
   native-download workflow); without it the owner forwards an unmanaged copy. Not hypothetical.
2. **Risk accepted:** yes: sharing within the organization and native download of all evidence
   are accepted decisions; the plan lists this increment.
3. **Typical:** yes, the same installations that use ADR-232 shares.
4. **Precedent:** an ACL read grant normally includes download (Google Drive, GitLab); general
   product knowledge.
5. **Privileges added:** none (0 SQL grants, 0 Kubernetes rights, 0 credentials). Recipients gain
   DownloadApproved of exactly the shared artifact version, only with `evidence:download`.
6. **Failure/degraded states added:** 0. A share-ledger outage refuses recipients only (as in
   ADR-232); downloads the ordinary facet admits never consult the share ledger.
7. **Self-configuration:** none.
8. **Outside Asservat's control:** none beyond ADR-232 (IdP subjects/groups).
9. **Aggregate cost:** downloads the ordinary facet admits: 0 extra reads. A recipient authorization: 2 indexed SQL
   share lookups (first and final check); within a content response at most 2 per 30-second
   reconstruction. 0 Kubernetes requests. Transfer bytes/sessions are charged to the existing
   per-workload allocation, so recipients cannot exceed the workload's download budget.
10. **Upgrade/rollback/disable:** no schema change. Rolling back the image refuses recipient
    downloads again. Disable by revoking the share, removing `evidence:share`/`evidence-owner`, a
    Deny AccessBinding, or withholding the `evidence:download` scope.
11. **Smaller fix:** documenting "ask the owner to forward the file" contradicts the native-download
    requirement and creates unmanaged copies; the branch reuses existing ports and is the plan's
    smallest form.

## Qualification

Results are in [implementation progress](../implementation-progress.md#s-06-increment-3-recipient-native-download-adr-233-2026-10-26).

## Limitations

- Revocation stops a running content response at the next 30-second reconstruction, not
  instantly (as for ordinary permission changes; ADR-220). Bytes already delivered are a local
  copy Asservat cannot delete.
- Recipients share the workload's download allocation with ordinary readers; there is no separate
  per-share budget.
