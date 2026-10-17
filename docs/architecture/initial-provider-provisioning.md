# Initial provider provisioning

This C-21 checkpoint extends [SQL preparation](initial-sql-provisioning.md) under
[ADR-128](../decisions/128-initial-provider-provisioning.md). It prepares original
provider credentials and a fixed immutable target projection. The original
installation Pod stays gated until the separate handover continuation succeeds.

## Protected inputs and actual producer

`InitialPreparer.providers` is optional, explicit installation configuration. It
selects one immutable bootstrap Secret UID, distinct issuer/encrypt/decrypt
policy names and distinct child token roles. Its public SHA-256 is held only as
private progress provenance; no credential or secret-payload hash enters the
public ConfigMap. All fields, source contents and provider endpoints are checked
before declaration. The actual `NewInitialPreparationDeployment` loads fixed
files, uses the pinned administrator/probe identities and composes SQL preparation,
`PrepareProvider` twice, then `PersistProviderProjection`.

The material Secret contains an existing non-root OpenBao issuer token and managed
S3 credentials. It is installation/request bound, immutable, at most 8 KiB, and
is never adopted or recreated. Current native administration and exact Secret
identity are required for reads. The selected JSON ACL profile has no wildcard,
HCL interpretation, `sudo`, identity-policy inheritance or default policy. The
issuer may read only the three selected ACLs and two roles, create against those
two roles, inspect itself and perform accessor lookup/revocation. Accessor APIs
cannot be scoped to an as-yet-unissued value by a static ACL; that credential
therefore remains exclusively in the trusted bootstrap process. No list-accessor
or root capability is used.

The child ACLs each contain only self-inspection plus the exact Transit encrypt
or decrypt operation. Roles fix service tokens, no default policy, no aliases,
no CIDRs, no orphan/renewal/period, zero usage count and a 900-second explicit max
TTL. The requested TTL derives from the original claim's latest completion and
original parent expiry, with one second of margin; it never renews on retry.
Policy reads use the pinned OpenBao 2.7.1 response: name/body, finite typed version,
CAS flag, optional modification time and the two identity-template flags. The
flags must both be false; unknown fields still deny. This first profile rejects
any policy expiration instead of manufacturing an extra policy renewal interval.
Modification/version metadata supplies no freshness or issue authority. The
[exact pinned response](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/logical_system.go#L2557)
and [current policy API](https://openbao.org/docs/api/system/policies/) distinguish
server wire fields from the exact ACL body whose meaning is checked separately.

Sending a second explicit max TTL alongside the role would produce a provider
warning, so the request uses the already checked role cap and its shorter TTL.
Every positive child is independently inspected with that child credential and
must retain its exact role, policy, operation metadata and finite original dates.

The parent's actual expiry must fit the original fifteen-minute SQL interval.
Positive child expiry must fit the parent end. Unknown late issue responses remain
uncertain and bounded by the original parent tree; client cancellation or another
lookup is not completion of an unknown POST. Native supported-version behavior
must be measured before this profile can be enabled.

## Private persistence and bounded ownership

After the existing positive SQL Secret reference, the private state accepts only:

1. One fixed provider profile digest and original parent accessor/issue/expiry.
2. One wrap claim, then its positive response.
3. One unwrap claim, then its positive response.
4. One final projection claim, then its exact original Secret UID.

Claims bind server-generated operation IDs and the original at-most-five-second
current interval. Every current observation retains its original deadline across
provider reads, Kubernetes CAS and final protection checks. A claim's original
expiry is never replaced by the next observation. At most two live positive
provider replies are retained; process closure prevents new ownership, cancels
and joins admitted calls, and clears the response map.

The private 16 KiB ceiling includes both maximum 1,024-byte provider tokens,
128-byte accessors and the final projection receipt. The producer checks the full
worst-case representation before its first provider POST. One immutable managed
material Secret and one final target Secret add a finite pair of setup objects;
they do not add unbounded public journal entries.

A lost issue-claim reply never sends a POST. A failed/unknown POST never retries.
A retained positive response can finish a lost private persistence write in the
same joined process. Another process needs the exact already persisted response.
No policy read, token accessor, absence or timeout manufactures that response.

The final Secret has exactly `sql-prepare.json`, `sql-audit.json`,
`sql-activate.json`, `audit-storage.json`, `audit-wrap.token`,
`audit-unwrap.token` and `kube-probe.token`. It contains no bootstrap issuer or
SQL maintenance credential. `kube-writer.token` remains the existing kubelet
projection. Unknown Secret CREATE permits only an exact read, preserving its
operation marker, immutable body and eventual pinned UID.

## Retirement boundary

The provider adapter exposes exact accessor revocation for a positively retained
original reply. It checks the current original issuer/profile, sends no issue or
renewal, and requires both explicit invalid-accessor rejection and rejection of
the original token's live authentication. A lost revoke response may be resolved
by those exact current observations. Generic HTTP failure or authentication denial
alone is insufficient. This is a rights reduction, not proof that earlier
Transit, SQL or object-storage effects did not occur.

Production composition must first join original issuers and establish the actual
activation owner's termination and effect disposition before credential cleanup.
The current checkpoint does not call provider revocation automatically, clear
private state or claim a completed retirement. Expired issuer/unknown issue
recovery still needs its separately accepted provider reconciliation path.

## Qualification and next continuation

The staged native fixture calls the actual fixed-file loader and `Run`, using real
Kubernetes, PostgreSQL and OpenBao. Bootstrap ServiceAccount/admin pin, initial
provider role/ACLs and managed S3 keys are explicitly fixture-provided. It checks
original loader replay, immutable projection, separate actual Transit purposes,
and exact child-token revocation after the preparation owners join while the Pod
remains gated. That revocation is provider evidence, not composed activation
retirement.
It does not execute the gated activation image or qualify S3 credential scope.
Unit TLS/CAS tests cover role/issuer/policy rejection, lost claims/replies,
concurrency, deadlines, private size and exact revocation. Actual commands/results
belong in the package handoff and implementation progress after they run.

Next: introduce an explicit new plan capability for kubelet writer TokenRequest
and staging-to-final handover, preserve all old compiled guard shapes, launch only
the recorded original Pod UID after joined request checks, observe the actual
initial-install result, and compose positive credential retirement. The retained
continuity policy must allow only the qualified writer request intersected with
the final policy's actual Pod identity; a broad token exception is not acceptable.
This checkpoint does not enable Helm runtime or public investigation routes.


## Role-only child lifetime lookup

The pinned OpenBao 2.7.1 token implementation applies a role's maximum lifetime
to the issued lease without copying that cap into the token entry's
`explicit_max_ttl` field. Its lookup can therefore return zero for a child whose
actual expiration is finite. The issuer itself still requires a positive
explicit cap. See the pinned [token store implementation](https://raw.githubusercontent.com/openbao/openbao/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/token_store.go)
(`parseAndMergeTTLPeriod` and lookup), separately from the general
[token API documentation](https://openbao.org/docs/api/auth/token/).

Only the exact role-issued child path accepts this zero field, after checking the
current 900-second role cap and exact ACLs. Nonrenewability, non-orphan status,
original parent identity, purpose metadata, role/path and actual issue/expiry
bounds remain mandatory. The correction adds no create retry, renewal or new
provider profile. Unit regressions retain the issuer-cap and unsafe-child denials.
The small `TestInitialProviderIssuerWithRealOpenBao` fixture now belongs to the
normal fleet selection; its actual before/after results must be recorded after
parent-owned qualification. The larger actual-loader fixture remains separate.


The pinned provider serializes an invalid-accessor backend error through its
single-error `go-multierror` wrapper. Retirement recognizes only the exact plain
message or that exact single-error representation, inside a parsed HTTP400
response. It rejects raw undecodable bodies, extra errors and altered text, then
still requires the original child token's separate live HTTP403 rejection.
An acknowledged revocation alone never completes retirement. This follows the
pinned [request error wrapping](https://raw.githubusercontent.com/openbao/openbao/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/request_handling.go)
and [HTTP error serialization](https://raw.githubusercontent.com/openbao/openbao/a5db72cef75c24b920ade02065b18dd8eb666bac/sdk/logical/response_util.go).
