# ADR-128: Original installation provider credentials and projection

Status: implementation checkpoint; staged tests and native qualification must be
recorded separately. Full preparation/activation/retirement remains in progress.

## Decision

Extend the protected initial preparer with one explicit provider profile and one
immutable bootstrap material Secret reference. For managed OpenBao, configure
separate fixed token roles and JSON ACLs for audit encryption and decryption.
The installation-only issuer token stays outside the activation Pod. Both child
credentials use actual provider-generated service-token values and accessors;
no custom token IDs, token listing, orphaning, periodicity or renewal.

Current provider reads must verify the exact role/ACL profile and the original
nonrenewable issuer expiry. That expiry must fit the original SQL interval before
any child claim. Persist each claim before its single POST. Keep the original
positive response privately, including its exact provider dates. An unknown
claim or POST response never permits a second issue; the same joined owner may
finish persistence of its retained positive response. An accessor does not
recover a missing secret.

Assemble exactly the seven existing `initial-install` private files from the
original probe, SQL Secret, positive provider replies and pinned managed S3
input. Persist one create claim, reconcile only exact immutable contents, and
pin the actual target Secret UID. This step does not remove a scheduling gate or
consume the installation witness.

Externally managed S3 keys are supplied, not issued or revoked by Asservat.
Their local `storageUseUntil` bounds use by this installation; it is not a claim
about provider expiry or deletion. The accepted bundled SeaweedFS profile still
requires its own credential lifecycle and backend qualification.

## Rationale and boundaries

OpenBao permits role settings to override create parameters, and caller-selected
IDs require elevated privileges. Its service-token accessors support inspection
and revocation without revealing the original token. Its token tree supplies an
additional parent lifetime/revocation bound. These are provider semantics to
qualify, not proof that a timed-out HTTP request drained. [Token API](https://openbao.org/docs/api/auth/token/),
[token lifecycle](https://openbao.org/docs/concepts/tokens/),
[policy API](https://openbao.org/docs/api/system/policies/). Exact policy-response
fields come from the [pinned 2.7.1 source](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/logical_system.go#L2557),
including typed version/CAS/time metadata and disabled template-expansion flags.
The first profile refuses policy expiration; policy metadata is not freshness.

The implementation uses the existing pinned OpenBao Go client; no new dependency
or general credential controller is introduced. Existing absent-provider
configuration and serialized private progress retain their shapes.

The healthy checkpoint prepares providers through the real fixed-file loader
and supervisor. Guarded handover, actual activation, joined credential
retirement, unknown provider issuance recovery, old-record reconciliation and
Helm packaging remain necessary. A stored Secret or successful preparation
result is never SQL activation, recovery acceptance or enabled collection.
