# Isolated technology experiments

Executed 2026-10-09 during planning. These small programs exercise dependencies against synthetic bytes and the real design contracts. They are not production services, capture mechanisms or a product skeleton. The [summary](results/summary.json) records actual exits, tool versions and input hashes; [technology research](../../docs/research/technology-selection.md) states what remains unproven.

## Actual results

| Experiment | Result | Limit |
| --- | --- | --- |
| Go standard-library JCS | PASS: numeric formatting, UTF-16 key order, idempotence, duplicate names and invalid Unicode rejection | Not the full RFC/domain corpus; numeric precision must be bounded before signing |
| Go canonical JSON Schema | PASS: all 41 contracts compile with remote loading denied; manifest positive/unknown-property/UUID checks | Not full Go/Python/browser corpus equivalence or hostile decoder qualification |
| Tink + zstd | PASS: synthetic round trip, tamper, truncation and wrong-AAD rejection | Sequential reader; no seek/read-at API exposed by the tested reader; no KMS/S3 |
| JWS | PASS: exact `Ed25519` header, signature verify, tamper/wrong algorithm rejection | No issuer/expiry/key rotation/peer authority integration |
| libpcap + PCAPNG | PASS: native compiler match/nonmatch/invalid expression and exact packet write/read | Synthetic Ethernet/IPv4/TCP only; **no capture interface opened**, no Gadget/BPF integration |
| Independently encrypted compressed frames | PASS: native range recovered from two of four frames; reordered/tampered/truncated frame rejected | In-memory index only, 3 MiB synthetic input; not a defined/qualified artifact format or performance benchmark |
| React + Aria + Query + Vite | PASS: static assets built with the locked set | Small button/state experiment only; bundler `use client` warnings retained, no browser interaction/accessibility test of this experiment |
| Direct OpenAPI → TS | Generator exit 0; strict tsc **FAILED**, ten recursive self-reference errors | Successful text generation alone is insufficient |
| Hoisted local OpenAPI → TS | PASS: generation and strict tsc with no skipLibCheck | Prototype adapter only; full semantic/negative corpus still required |
| OpenAPI → Go | **FAILED** direct nested references; full hoisting still fails a multi-type schema union | Keep explicit Go DTOs plus authoritative schema validation, not weakened schemas |
| Initial npm resolution | **FAILED** TypeScript 7 with generator peer range `^5.x` | Compatible 5.9.3 pinned; no force/legacy-peer-deps used |

Six Go tests passed. No SQL server, identity provider, object store, KMS, encrypted CSI, VM, Kubernetes cluster, root privilege or host crash configuration was involved. Do not infer workload impact or download throughput from the tiny synthetic runs.

## Reproduce the passing checks

Prerequisites: Go 1.27 with a C compiler and libpcap development files, Python with PyYAML, and a Node version supported by the lockfile. Initial dependency downloads require configured network/mirror access; these dependencies should be mirrored for offline builds. Do not install host packages or run privileged tests merely to rerun these checks.

From this directory:

```sh
cd go
GOTELEMETRY=off GOTOOLCHAIN=local go test -count=1 -v ./...
```

From the workspace root, choose temporary output paths that do not contain evidence:

```sh
npm --prefix experiments/technology-selection/web ci --ignore-scripts --no-audit --no-fund
npm --prefix experiments/technology-selection/web run build
python3 experiments/technology-selection/contracts/bundle.py --hoist /tmp/asservat-openapi-hoisted.json
experiments/technology-selection/web/node_modules/.bin/openapi-typescript /tmp/asservat-openapi-hoisted.json -o /tmp/asservat-browser-types.d.ts
experiments/technology-selection/web/node_modules/.bin/tsc --noEmit --strict --lib es2022,dom /tmp/asservat-browser-types.d.ts
```

`contracts/bundle.py` only produces an experimental local bundle. Hoisting copies the referenced schema nodes into named components and redirects exact JSON Pointer references; it does not edit canonical contracts or remove validation keywords to accommodate a generator. Production adoption requires semantic corpus tests. The strict compiler check deliberately does not skip declaration checks.

To reproduce the rejected Go generator attempt against that hoisted bundle:

```sh
GOTELEMETRY=off GOTOOLCHAIN=local go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 -generate types -package generated /tmp/asservat-openapi-hoisted.json
```

Expected outcome at the recorded versions: nonzero exit on the schema's multi-type union. This is retained as a selection finding, not a passing gate. Omitting `--hoist` reproduces the earlier nested-reference problem and the TS declaration errors.

At the time of this isolated experiment there was no product Go or frontend workspace. The root Go module has since been added; the production frontend workspace remains pending. The modules here are intentionally isolated; generated bundles/node_modules/dist are disposable outputs. Libraries, transitive packages and image/toolchain pins still need the [maintenance and security review](../../docs/research/dependency-maintenance.md) before a production lock.
