# Pinned OpenBao policy metadata and bounded loader diagnostics

Seven frozen paths in changes/, exact hashes in manifest.json, unified patch.
Original ADR128 package is unchanged. No live edit/external fixture occurred.

## Reproduced defect and correction

The actual pinned OpenBao v2.7.1 revision
`a5db72cef75c24b920ade02065b18dd8eb666bac` always returns policy version,
CAS-required and two template-expansion flags besides name/policy, with optional
modification/expiration times. The earlier closed two-field DTO rejects that
legitimate response. Exact source:
https://raw.githubusercontent.com/openbao/openbao/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/logical_system.go
(`readPolicyResponse`, lines2557-2575 in the retrieved pinned source).
Current primary docs: https://openbao.org/docs/api/system/policies/ and
https://openbao.org/docs/api/auth/token/ .

`TestInitialProviderPinnedACLReadMetadata` failed before the DTO correction at
`initial provider preflight policies: unavailable`; real exit1 is retained in
pinned-acl-before.log. This is a deterministic incompatibility. The earlier native
loader's generic error did not identify its exact phase, so a passing native
rerun remains necessary to confirm complete provider composition.

The DTO now requires explicit typed name/body/version/CAS/template flags, accepts
optional typed modification metadata, requires both template flags false and
rejects any actual policy expiration for this first qualified profile. Version
must be nonnegative. Exact ACL body/purpose comparisons, closed unknown-field
rejection, finite body limits, original issue/parent deadlines, one-use claims
and no-replay behavior are unchanged. These metadata fields never extend
freshness or confer authority.

Loader diagnostics now identify only fixed local phases. Provider preflight has
fixed wrap-role/unwrap-role/policies/issuer-profile/final-deadline labels. Errors
preserve errors.Is via Unwrap without rendering raw nested causes, SQL, source
names, provider response bodies, request values or credentials. The CLI's
existing fixed remedy classification remains unchanged. Provider Check's cause
is no longer discarded at the loader boundary.

## Actual checks

All Go commands use TMPDIR=/home/phil/.cache/asservat-build/tmp, GOMAXPROCS=2,
-p2 and overlay.json. No external fixtures.

- Before: go test ./internal/adapters/kms
  -run '^TestInitialProviderPinnedACLReadMetadata$' -count=1: exit1, intended
  rejected pinned response (pinned-acl-before.log).
- After: go test -race ./internal/adapters/kms ./internal/bootstrap
  -run 'TestInitialProvider|TestInitialPreparer' -count=1: exit0;
  kms1.592s, bootstrap1.053s (fixed-race.log).
- go vet for those two packages: exit0 (vet.log).

Regression negatives include enabled template expansion, past/future expiry,
negative/fractional/string version, invalid date and unknown authority field;
all deny before issuance. Diagnostic tests preserve original error identity and
exclude synthetic secret-bearing causes. Existing issuance/CAS-independent
provider role, purpose, deadline and revocation tests are included.

Parent next: integrate hashes, run exact
`^TestInitialPreparationProvidersWithRealServices$` in the owned native lab.
No native result is claimed by this correction. ADR129 handover source remains
separate and unfrozen; it must refresh these two production files as dependencies.
