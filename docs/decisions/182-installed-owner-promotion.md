# ADR-182 — Promoting the installed owner to native backend and public layers

Date: 2026-10-15. Status: accepted; promoted composition and public provider purposes implemented with unit tests; installer producers and native qualification pending.
Requirements: S-02, REQ-DEP-003, REQ-FED-001; TASK-03 / TASK-11.
Builds on [ADR-140](140-installed-public-runtime-producers.md)/[144](144-cluster-local-observations.md),
[ADR-171](171-hub-run-context-execution.md) and
[ADR-180](180-hub-api-public-composition.md).

## Context

The installer starts the hub-api in observation mode. That process is
identity-only:

- provider-authenticated audit and owner PKI;
- owner proofs;
- regional observation.

It has no native listener payloads, context-start route, worker routing,
native downloads or public layer. Those run only in the legacy full mode,
which reads static OpenBao tokens that no installer produces. Three input
rules today make the two layers impossible to combine:

- `Public` requires `Native`.
- `Native` excludes `Observation`.
- `ProviderAuthentication` requires `Observation`.

The installed template already reserves the means for both layers: optional
observation and public projection Secrets at `/run/asservat/owner-observation`
and `/run/asservat/public`, the native port 9444 and the public port 9445.
[installed-owner-identity.md](../architecture/installed-owner-identity.md) states
that backend and public promotion require positive projection receipts. Volume
presence does not count.

## Decision

1. **One installed hub-api with ordered layers.** (Amended during
   implementation: see Progress.) The installed process always
   composes the identity layer as today. Two more layers follow when promoted:
   - **Backend layer:** worker routing, native exchanges, context-start
     ingress and download-peer proofs.
   - **Public layer:** ADR-180.

   A layer is enabled only by a positive projection receipt for it in the
   original resource journal. Startup verifies the receipt with the same
   current journal read as the identity projection. A missing or
   unacknowledged receipt keeps the layer off; there is no file-presence
   fallback.
2. **Inputs per layer from their fixed roots.**
   - The backend layer reads only `/run/asservat/owner-observation`: its SQL
     logins (`routing`, `native-read`), `worker-controls.json` and the pinned
     worker-namespace tokens.
   - The public layer reads only `/run/asservat/public`: the ADR-180 files,
     the public runtime role projection and the public audit keys.
   - The deployment input stays in the identity ConfigMap, and its `Native`
     and `Public` sections must match the receipts.
3. **Fixed ports.** Native and observation traffic use 9444 and are
   multiplexed by exact path on one listener. The public layer uses 9445. The
   `Public.Port` input must equal 9445 in the installed layout.
4. **Provider authentication everywhere.** In the installed layout no static
   OpenBao token is read.
   - The identity layer keeps its four provider lifetimes.
   - The public layer adds its own provider-authenticated purposes: browser
     session seal and open, work signing and worker PKI. Each is a separate
     OpenBao role and policy, provisioned by the installer and bound to the
     owner's Pod token.
5. **The input rules change accordingly.** `Native` and `Public` become
   allowed together with `Observation` and `ProviderAuthentication`, but only
   in the installed layout and only with their receipts. The legacy
   static-token full mode stays available for existing fixtures. It is never
   produced by the installer.

## Consequences

A promoted installed hub-api holds the identity, backend and public
credentials of its layers in one process, as ADR-177 already accepts for one
process. Promotion is a new installer step with its own receipts. Rolling back
a layer means withdrawing its projection and restarting. The process never
downgrades itself at runtime.

## Implementation

1. **Contracts and validation:** installed-layout layer rules and fixed ports.
2. **Bootstrap:** a single installed composition that runs the identity layer,
   then the backend layer (`OwnerRuntime` with native and context-start)
   and the public layer, each from its root, on one 9444 listener plus 9445.
3. **Provider effects** for the public purposes.
4. **Installer:**
   - receipts and producers for the observation and public projections;
   - the owner `routing` and `native-read` roles with connector-registry
     reads;
   - every public input listed in ADR-180.

## Progress

- **Receipts amended.** The verified, immutable identity deployment input is
  itself the positive receipt. Its `Native` and `Public` sections enable the
  backend and public layers, and the installer writes those sections only
  after the layer's projection is complete. Volume presence alone still
  enables nothing; a missing projection root or file fails startup.
- **Inputs.** `readOwnerInputs` admits `Observation`, `ProviderAuthentication`,
  `Native` and `Public` together only in the installed layout. In that layout
  the public port must equal 9445 and the public provider recipe must match.
  The legacy layout keeps the exclusivity and never carries a recipe. Unit
  tests: `TestInstalledOwnerPromotionInputs`, the provider and public input
  tests.
- **Public provider recipe.** `providerconfig.OwnerPublicProviderRecipeFor`
  (`asservat-owner-public-provider-recipe/v1`) covers four roles and policies:
  browser seal and open, work signing, and worker PKI. It is bound to the
  identity recipe digest and leaves that digest unchanged.
- **Provider effects.** `kms.InstalledOwnerProviderEffects` adds the four
  public lifetimes under the same supervision. `BrowserSealer`,
  `BrowserOpener`, `WorkSigner` and `WorkerIssuer` are each confined to their
  path (`TestOwnerProviderPublicPurposesAreSeparateAndConfined`).
- **Composition.**
  - `composeOwnerIdentity` is extracted unchanged from the observation
    deployment.
  - `NewOwnerDeployment` runs the installed identity startup for a promoted
    input, governs its identity pools, and reads backend and public inputs
    from their projection roots.
  - It uses provider effects instead of token files, and an audit store with
    provider-held credentials.
  - It primes and supervises the providers in `Run` and joins them in
    `Close`.
  - `RunHubAPI` routes identity-only installs to the observation runtime and
    promoted installs to the full composition.
- **Open.** In a promoted process the identity layer's observation owner
  handler (bootstrap name on 9444) is not served. No product consumer uses it
  yet; serving both names on one port needs SNI dispatch first.
