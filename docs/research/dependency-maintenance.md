# Dependency maintenance review

The maintainer explicitly prefers established, actively maintained libraries and does not want to start with abandoned dependencies. This is a selection criterion alongside capability, licence, security and integration cost. Snapshot date: 2026-10-09. [Observed repository metadata and recent commits](dependency-maintenance-snapshot.json) retain the source URLs and dates; [version metadata](technology-source-snapshot.json) records the earlier release/package checks.

## Selection rules

Prefer the supported standard library, then established upstream projects with current maintenance, substantive fixes, maintained release branches and a usable security-reporting path. Check the branch/version actually imported, not just activity elsewhere in the organization. Prefer stable releases and a resolved compatible dependency set; a recently published major release or prerelease transitive module needs additional scrutiny.

Do not select an archived, explicitly unmaintained, unsupported or effectively abandoned project for a new production dependency. An old last-release date alone does not prove abandonment for a small completed standard implementation, but it does require evidence of ongoing issue/security handling. Stars, downloads, an organization logo, automated dependency bumps and a recent `pushed_at` are supporting signals, never a maintenance verdict by themselves.

Before the first production lock, review unresolved relevant security/correctness issues, supported Go/Node/Kubernetes versions, response/patch history, exact transitive dependencies and licence files. Record an adapter owner and replacement path. Refresh at release time and when a security advisory or upstream maintenance change occurs. Do not use floating versions, silently force incompatible peer dependencies or vendor an abandoned package and describe it as third-party maintained. Vendoring/mirroring for reproducibility does not transfer upstream maintenance to Asservat.

## Findings and decisions

The 2026-10-10 [small-deployment follow-up](small-deployments.md#maintenance-snapshot) checks SeaweedFS, PostgreSQL image sources, pgBackRest, CloudNativePG, ZITADEL OIDC, go-webauthn and Fosite. It records exact observed releases, maintenance caveats, rejected archived MinIO and unsupported Bitnami Legacy image defaults. These are new candidates, not additions to the production lockfile or completed security/runtime qualification. ZITADEL's library does not require operating the ZITADEL service; the local identity integration still needs actual MCP and security tests.

| Dependency family | Evidence observed | Selection |
| --- | --- | --- |
| Canonical JSON | The cyberphone reference repository's last observed push is December 2024; the five inspected commits are mainly old project/Python changes. The gowebpki fork has recent fixes but is still a small extra dependency. Go 1.27 provides the needed RFC 8785 operation directly | **Use standard-library `encoding/json/jsontext.Value.Canonicalize`**. Neither external canonicalization package is selected. Local samples passed including numeric formatting, UTF-16 ordering and duplicate/invalid Unicode rejection. Full domain numeric/cross-language fixtures remain a gate. [Official API](https://pkg.go.dev/encoding/json/jsontext#Value.Canonicalize) |
| Packet decoding/PCAPNG | `gopacket/gopacket` has history since 2022, October 2026 substantive bounds/read-path fixes and multiple authors in the inspected commits; the older Google repository shows substantially older push activity | **Keep the maintained fork**, behind the format/mechanism adapter. Do not import the older Google module by habit. Neither repository was flagged archived in the API snapshot; the choice is based on maintenance evidence, not an invented archival claim. [Maintained upstream](https://github.com/gopacket/gopacket) |
| JWS | jwx repository dates to 2015; inspected October 2026 commits fix numeric parsing. v4 provides the specified explicit Ed25519 algorithm; maintainer concentration and a newer major version remain considerations | **Keep as a qualified candidate**, not an unsupported homegrown JWS implementation. The experimental lock contains `option/v3 v3.0.0-alpha1` transitively; review that dependency and the current supported stable combination before a production lock. Reject optional experimental algorithms/plugins. [v4 announcement](https://github.com/lestrrat-go/jwx/discussions/2040), [source](https://github.com/lestrrat-go/jwx) |
| JSON Schema | santhosh-tekuri/jsonschema dates to 2017; recent inspected history includes v6.0.3 release work and a September 2026 code optimization from another contributor | **Keep v6 candidate**: established implementation, current activity and actual 2020-12 contract compilation. It remains a smaller maintainer-led project; monitor patch handling and retain a narrow validator adapter. [Upstream](https://github.com/santhosh-tekuri/jsonschema) |
| DSSE | go-securesystemslib has several human contributors in the inspected September 2026 history, a key-type panic fix, Go version work and dependency updates | **Keep candidate** behind an attestation adapter; this pass did not integrate its API or complete its security review. [Upstream](https://github.com/secure-systems-lab/go-securesystemslib) |
| SQL/identity | pgx, sqlc, goose and go-oidc are unarchived with September/October 2026 push activity; pgx/goose/go-oidc have recent release candidates recorded in the version snapshot | **Keep established families**. sqlc is a build tool, goose is migration-only, pgx is the runtime database adapter. Detailed supported-branch/security review is still required before product pins |
| Kubernetes/Gadget/MCP | controller-runtime, Inspektor Gadget and the official MCP Go SDK show current activity and releases; the SDK's own history is shorter than Kubernetes' | **Prefer the official maintained integrations**. A younger official SDK can be preferable to an older unofficial client; retain strict protocol/version and engine qualification |
| Cryptography/compression | Tink Go and klauspost/compress show October 2026 activity and tagged versions; CEL and Bleve also show current activity | **Keep candidates**. Tink supplies cryptographic primitives; compression/CEL/index parsers remain bounded, fuzzed interfaces. Maintainer concentration still matters for community libraries |
| Console | React, Adobe React Spectrum/Aria, TanStack Query, React Router and Vite have current repository activity; openapi-typescript has September activity | **Keep established ecosystems**, use a compatible locked set, avoid a new all-in-one dashboard framework. Generator output must compile and preserve contract meaning; project health does not imply schema compatibility |
| S3/KMS and OS parsing | AWS SDK v2, OpenBao and prometheus/procfs show current activity | **Keep first-party/established clients** with explicit endpoints. Object-store/IdP/CSI deployments and optional diagnostic pack dependencies retain separate operational support reviews |

All 28 queried repositories returned metadata and none was marked archived/disabled in this snapshot. Six smaller or competing projects additionally had their latest five default-branch commits inspected. That is a bounded maintenance screen, not an audit of every contributor, issue response time, release branch, transitive package, diagnostic tool or container image. No project is declared security-certified or indefinitely supported from these signals.

## Practical consequences for the plan

Remove external JCS from the planned runtime dependency list. Keep libpcap's established language/compiler rather than inventing a filter implementation. Use the maintained packet fork, official Kubernetes/MCP clients, standard Go HTTP/JSON and a small number of established UI libraries. Do not add a bespoke schema compiler to work around generator limitations: use explicit Go DTOs plus the maintained schema validator; limit build-time reference adaptation to preserving schemas for TypeScript generation.

The remaining small-library concerns are visible in the technology table and release gates. If a candidate cannot meet the supported-version/security-maintenance check, replace it behind its adapter before enabling the feature. Do not defer that decision to operators after deployment.

## First implementation refresh

The initial product lock is [go.mod](../../go.mod), with Go 1.27.2 and x/net v0.60.0 selected after a reachable-vulnerability scan flagged the dependency minimum v0.58.0. Primary [Go advisory](https://pkg.go.dev/vuln/GO-2026-6610) and [scanner documentation](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) informed this update. The [artifact implementation record](artifact-foundation.md) records the final scan and runtime checks; earlier experimental locks are historical evidence, not new-product dependency recommendations. The scanner is a development tool and creates no runtime call-home path.

The final initial-component scan found no reachable known vulnerabilities. One module-only advisory remains for the **unused** `golang.org/x/crypto/openpgp` package (GO-2026-5932, no fixed version); the build import gate forbids that package transitively. This does not reject the maintained HKDF and other x/crypto primitives used by the chosen libraries. Full release/image/supply-chain qualification remains separate.

## Implementation refresh, 2026-10-10

The initial work-verification adapter now pins jwx v4.5.0 with an explicit review of its current option/v3 alpha dependency; the token adapter pins go-jose v4.1.5 after its security update. See [signed-work implementation evidence](signed-work-foundation.md) for the inspected source, primary references, actual tests and remaining key/peer qualification. This supersedes candidate-only status for the narrow JWS verifier, not for the complete fleet protocol.

## Initial SQL credential refresh, 2026-10-11

[ADR-100](../decisions/100-temporary-initial-sql-credentials.md) pins
[`github.com/xdg-go/scram` v1.2.0](https://github.com/xdg-go/scram/tree/v1.2.0)
only for deriving PostgreSQL stored SCRAM-SHA-256 verifiers. pgx continues to
implement connection authentication. This established Apache-2.0 library is not
archived or disabled in the inspected upstream metadata. Its last inspected
push was 2025-11-24T13:41:16Z and v1.2.0 was published that day; the inspected
history includes SCRAM-PLUS and error-handling maintenance. That is roughly ten
months without a later observed push, not evidence of frequent ongoing commits.
The protocol is mature, but maintainers and security response remain a release
review obligation. No abandoned fork or handwritten SCRAM implementation is added.

The [tagged client](https://github.com/xdg-go/scram/blob/v1.2.0/client.go)
exposes `GetStoredCredentialsWithError`; its initial client error can contain an
invalid input password. Asservat first accepts only canonical generated ASCII
secrets and always returns opaque errors. The tagged Go >=1.24 build uses the
standard-library `crypto/pbkdf2`; `xdg-go/pbkdf2` remains in the module graph for
older build tags but is not selected by our Go toolchain. `xdg-go/stringprep`
v1.0.4 is also retained transitively. These graph facts are distinct from a claim
that every historical build mode is audited.

The [initial scan](../../test/results/initial-role-vulnerability.log),
`make go-vuln-check`, reported no vulnerabilities in imported packages or called
symbols. It still reports the previously documented module-only advisory in an
unused package. The [provider regression](../../test/results/initial-role-ambient-after.log)
qualifies actual PostgreSQL SCRAM authentication, unchanged replay and retirement,
including indirect PUBLIC grants and application SECURITY DEFINER rejection.
This is not a complete supply-chain or production-installation certification.

## Console and MCP implementation refresh, 2026-10-11

The new product `web/package-lock.json` pins the established React/Vite/React
Aria families rather than adopting a dashboard framework. Registry inspection
selected React 19.3.0, React Aria Components 1.22.1 and Vite 8.3.4. The inspected
React, Adobe React Spectrum, Vite, Vitest, AJV and Playwright upstream repositories
were not archived and showed September/October 2026 updates. This is a bounded
maintenance screen, not a support guarantee.

TypeScript 7.0.2 failed npm's dependency resolution because openapi-typescript
7.13.0 declares TypeScript 5. The product uses the already selected TypeScript
5.9.3 without overriding peer checks. Build-only AJV 8.20.0 and ajv-formats 3.0.1
generate schema validators; their required runtime helper code is bundled into
the static assets. There is no browser-side schema compiler or remote schema
fetch. The smaller ajv-formats helper's latest inspected release is from March
2024; release age alone is not a claim of active maintenance or abandonment.
Its format behavior is covered by generated-contract and browser tests.

The full npm dependency audit and production-dependency audit both reported zero
known vulnerabilities in [the recorded full report](../../test/results/console-dependency-audit.json)
and [runtime report](../../test/results/console-runtime-audit.json). The full
report matters because generated validators bundle helpers from build-time
dependencies. Audits do not establish the absence of unknown vulnerabilities.
Dependency lifecycle scripts are disabled by the workspace `.npmrc`; the build
and actual browser qualification succeeded under that setting.

The [MCP runtime contract](../architecture/mcp-runtime.md) records the official
Go SDK v1.8.0, its four added upstream transitives, preserved existing pins,
license inspection and passing targeted call-graph vulnerability scan.

Primary build/validation references:
[Vite production build](https://vite.dev/guide/build),
[AJV standalone validation](https://ajv.js.org/standalone.html),
[React Aria source](https://github.com/adobe/react-spectrum),
[OpenAPI TypeScript](https://openapi-ts.dev/introduction).
