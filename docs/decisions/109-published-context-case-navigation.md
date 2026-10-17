# ADR-109: Published context cases and ordinary navigation

- Status: accepted for implementation; external qualification pending
- Date: 2026-10-11
- Requirements: REQ-EVD-004, REQ-MCP-005; S-02
- Owner: C-16 Catalog and history

## Decision

Add an indexed publication-only case-to-artifact/target projection and one C-16
ordinary context case service. Preserve existing whole-pod eligibility, current
complete denies, retained audiences and effective retention. C-09 navigation
consumes that service through its own narrow port and never exposes a candidate
case UUID solely because collection succeeded.

Migration 00038 derives one immutable locator from the accepted expectation
inside the existing catalog publication transaction. Backfill uses published
catalog entries only. The SQL routing facet has no metadata/evidence authority;
current ordinary rights precede verified catalog lookup. Unpublished uploads,
raw artifacts and shares cannot fall back to ordinary metadata. No native
preparation, decryption, filename or native checksum is required to view a case.

Clarify the existing outward artifact `digest` as the immutable verified artifact
version, distinct from native SHA-256. The initial context profile reuses the
existing SHA-256 of its versioned ciphertext-copy receipt serialization. Native
checksums remain part of independently authorized, charged download preparation.

The service returns at most 100 visible approved pod-status descriptors, only
while original caller/current permission, retained policy and recovery bounds
remain valid. Known rights/revision changes deny delivery. The transport inherits
the original metadata deadline; it cannot create a new five-second window.

## Reasons and tradeoffs

Case IDs already exist in immutable encrypted manifests and accepted context,
but no indexed association or ordinary metadata coordinator existed. Scanning
all captures or returning custody candidates would add both friction and an
existence oracle. The publication projection supplies only the trusted internal
routing needed for the existing evaluator; it does not introduce a second policy
engine or require download authorization for ordinary metadata browsing.

The first service is deliberately one verified profile. The bound rejects an
oversized case rather than silently truncating it; future grouping/search needs
an explicitly paginated contract. Safe case metadata retention, alias/correlation
and encrypted titles remain pending. NO ACTION foreign keys and immutable rows
preserve historical dependencies until the metadata retirement owner proves a
safe deletion protocol. One locator remains covered by its accepted capture's
existing finite control slot; publication does not allocate an unbounded side
history.

## Verification

See [ordinary context cases](../architecture/context-cases.md) for focused tests,
external-fixture scope and remaining runtime composition. Compile-only fixture
success is not real-service qualification or public enablement.
