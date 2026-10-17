# Identity and eligibility component record

Date: 2026-10-10 (work begun 2026-10-09). This continues the [manifest foundation](manifest-foundation.md) with the first caller-identity and ordinary-permission components. The [architecture contract](../architecture/identity-eligibility.md) records exact bounds, provider assumptions and missing production adapters. This is partial TASK-07 / S-01/S-02 work; accepted execution, durable audit and publication remain unimplemented.

Subsequent correction: the [permission continuation](permission-foundation.md) found and fixed an overly long deny-cache allowance, with a failing regression preserved. Complete deny snapshots now have an independent five-second interval. Its concrete Kubernetes observation readers still do not supply accepted authorization projections. The verification below remains the original step's historical record.

## Research and library choice

Reuse the selected **coreos/go-oidc v3.21.0**, with **go-jose v4.1.4** for JWK parsing and the verifier's signature implementation. These are the established families already selected in the [dependency review](dependency-maintenance.md), now pinned in the product module. `golang.org/x/oauth2 v0.36.0` is transitive; no browser OAuth flow was implemented by importing it. See [go-oidc upstream](https://github.com/coreos/go-oidc), its [API](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc), and [go-jose's pinned API](https://pkg.go.dev/github.com/go-jose/go-jose/v4@v4.1.4). Provider interoperability and full release supply-chain review remain separate gates.

[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html#section-4) distinguishes JWT access tokens through their media type and requires issuer, audience, signature and expiration checks. [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.12) requires distinct validation rules to avoid confusing JWT purposes. Therefore Asservat adds resource-server checks around the library's OIDC verifier; accepting whatever an ID-token verifier accepts would be insufficient.

Media types are case-insensitive under [JWS section 4.1.9](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9); the adapter accepts `at+JWT` as well as `at+jwt`, without case-folding issuer/subject/client/group identifiers. [JWK key operations](https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3) constrain key use; the initial adapter rejects a supplied sign-only key operation. Its exact limits, single-audience profile and complete-group assertion requirement are Asservat implementation bounds, not universal OAuth requirements. Do not impose this test profile on a provider by claiming generic OIDC compatibility.

## Implemented

- `internal/adapters/oidc`: strict bounded JWT/JWKS parsing, verified TLS to a configured endpoint, finite key snapshots/refresh, RS256 verification and explicit access-token/client/time checks. Token-controlled URLs, private JWK material, ambiguous fields and ID tokens fail closed.
- `internal/application/identity` and `internal/domain/identity`: verified principal values, current organization/client eligibility, finite group/key/policy deadlines and sanitized errors.
- `internal/application/authorization` and `internal/domain/authorization`: current ordinary whole-pod eligibility, required scopes, deny precedence and original/current audience intersection for approved evidence. Preliminary checks prevent unauthorized evidence lookups. Contributing assignments are not a complete capture audience or an effect permit.

There is no runtime policy/configuration/catalog fake or permissive authority fallback. Test projections are synthetic and isolated in `_test.go` files. No SQL migration, public operation, UI screen, grant or storage format changes in this step. Identity/permission settings remain Kubernetes-owned.

## Verification and defects corrected

The focused tests use actual RSA signatures and a local HTTPS/JWKS server with certificate verification. A combined flow runs the concrete token adapter through identity admission and permission evaluation: an ordinary developer qualifies for context and approved native download; another team cannot probe the artifact; new ownership cannot expose older evidence; an A → B → A assignment cycle cannot resurrect access; current client removal stops evaluation before workload lookup. Its configuration and retained evidence are **test projections**, not an actual IdP, Kubernetes permission controller or catalog.

Other cases cover wrong issuer/resource/client binding, missing/expired/future timestamps, ID/untyped tokens, signature or subject tampering, attacker-selected key URLs, duplicate/case-aliased JSON fields, missing/null/oversized groups, scope ambiguity, TLS trust, redirects, oversized/private/duplicate/incompatible JWKs, key rotation/outage, 40 concurrent unknown-key requests, expiry/cancellation/clock rollback during a blocking fetch, current group/ownership changes, explicit and stale denies, cross-cluster/namespace/pod substitution, audience overflow and raw-operation rejection. Deadline checks run again after blocking configuration/evidence reads.

Failing tests first demonstrated these defects in the initial implementation, then passed after correction:

- Artifact provenance was read before rejecting absent entitlement, missing scopes or explicit/unknown denies. The evaluator now performs ordinary scope checks before any evidence lookup.
- The token parser treated a missing group assertion as empty membership. The profile now requires an explicit complete assertion; provider semantics still require qualification.
- The key parser ignored an incompatible `key_ops`, and media-type matching incorrectly rejected the standard's `at+JWT` spelling. Both are corrected without relaxing identity comparisons.
- An unexpected token-adapter error could escape with private text. The identity service now returns canonical error values.
- Growth in current assignments could apply the new-capture audience limit before an old artifact was looked up, unnecessarily blocking a still-valid original reader. Read preflight now permits the bounded current projection; the final result remains restricted to the artifact's original, bounded audience. [Failing regression](../../test/results/identity-audience-growth-before-fix.log).

The before-fix logs are [initial token tests](../../test/results/identity-initial-tests.log), [lookup/token regressions](../../test/results/identity-regressions-before-fix.log) and [error projection](../../test/results/identity-error-regression-before-fix.log). The [focused flow log](../../test/results/identity-focused-tests.log) records the corrected cases; the final [Go gate](../../test/results/identity-go-check.log) also includes subsequent signature-tampering and multiple-team tests. The first full vet run additionally required keyed external test-struct literals; those were corrected before the final gate.

`make go-check go-architecture-check sql-check` passed: embedded-schema parity, vet, all ordinary race tests, 17-package/26-edge import ownership and three unchanged sqlc outputs. External Kubernetes/S3/PostgreSQL fixtures are explicitly skipped by ordinary `go test`; they were not rerun because their adapters/SQL were unchanged. Their earlier measured records retain their original source hashes and are not described as new end-to-end identity tests.

`go test ./internal/adapters/oidc -run '^$' -fuzz '^FuzzAccessTokenSyntax$' -fuzztime=15s -parallel=2` passed **313665 executions** in approximately 16 seconds. [Fuzz log](../../test/results/identity-fuzz.log). This samples parser robustness, not complete parser security or production load qualification. `make go-vuln-check` found zero affected code/imported packages; the existing module-only advisory is still subject to the prohibited OpenPGP import gate. [Vulnerability log](../../test/results/identity-vuln-check.log).

All seven design gates passed: specification, architecture, design, OpenAPI, downloads, combined investigation and live watching. The specification gate checked 43 schemas, 155 examples, 171 requirements/scenarios and 329 rejected invalid examples. [Design log](../../test/results/identity-design-checks.log). These remain design/contract checks, not production permission or disclosure tests. No privileged collector, external identity service, paid resource, Kubernetes cluster or Docker fixture was created during this step. Local TLS test servers close when their tests finish. No real user tokens or evidence were used.

## Still required

Qualify the actual operator-selected IdP: access-token distinction, discovery/resource metadata, registered-client semantics, group identity/refresh, user removal, key removal, browser login/session/CSRF, step-up and workload identity. Implement accepted Kubernetes configuration readers, namespace/SAR inheritance, deny completeness, durable assignment transitions and signed accepted execution. Then wire durable audit and authorized catalog publication, followed by current-authority UI/MCP/native downloads and qualified cleanup. Library signatures and synthetic current-policy values alone do not authorize a production collection or evidence read.
