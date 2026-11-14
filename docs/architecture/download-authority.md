# Download authorization

C-03's `ContextDownloadAuthority` makes the ordinary access decision for a download of published evidence. It uses domain values and consumer-owned ports; it has no SQL, Kubernetes, OIDC, object-store or transport dependency. Missing readers deny access.

## One decision per operation

Each public download operation (session creation, metadata view, content GET) is authorized once, as [ADR-311](../decisions/311-operation-authority-recheck.md) and [ADR-330](../decisions/330-event-driven-system-design.md) D5 specify:

1. Authenticate the caller once at ingress: the exact human or workload and the OAuth client bound to the request.
2. Evaluate current target permissions, denies and download scopes from the permission projection.
3. Load the published catalog entry: capture, artifact/attempt, exact Pod/workload/namespace, ciphertext version, diagnostic purpose, original retained audience, stored effective deletion deadline and retained policy references. The projection contains no native file content, checksum or filename. Unpublished custody records cannot produce it.
4. Evaluate ordinary rights against the original audience. Newer ownership alone does not grant access to older evidence.
5. Check the [download environment](download-environment.md): delivery policy, processing restrictions and region/store path.
6. Read the [recovery fence](download-recovery.md) epoch the operation runs under.

The result is a `DownloadAuthority` that binds principal/client, artifact/attempt/store, region, policy revision, recovery epoch and a content-minimized decision digest. It is reused for at most `identity.AuthorityRecheckInterval` (30 s; 60 s for the shared delivery-policy observation; maintainer decision ADR-311) and never past the earliest original deadline: browser session expiry, download session deadline and `AccessUntil`. A later operation authorizes again. Blocking reads inside one operation do not trigger another identity or permission read.

`AccessUntil` is the stored effective deletion deadline, narrowed to an admitting share's expiry or the raw grant child's end. Acquisition may have ended; download remains available until that deadline.

## Started responses

A content response is fully authorized before its first byte ([ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md)). It then runs without identity, permission, share or policy reads until an original bound ends it: browser session expiry, download session deadline, `AccessUntil`, a shortened stored deletion deadline, Stop, a recovery epoch change, or the end of the selected range (for raw evidence, exhaustion of its raw-pool reservation). Stop, retention shortening and recovery changes reach a running response as events (ADR-330 D1). Access-token expiry does not end a started response ([ADR-335](../decisions/335-usable-by-default.md) D9).

## Shares

When ordinary target eligibility refuses, the caller's own concrete shares of exactly the requested artifact and version are read ([ADR-233](../decisions/233-recipient-native-download.md)). No admitting share means no catalog lookup. After the catalog read the share must name the artifact's case and its managing team (stable group ID) must be in the original audience. The decision digest binds the share ID and revision; `AccessUntil` ends no later than the share's expiry. Current denies win and `evidence:download` is required. Share downloads, like ordinary ones, have no transfer byte budget (ADR-335 D9).

## Effects

The authorizer emits no bytes and reserves nothing. The SQL effect transaction that starts a session or response compares the authorized recovery epoch and stored deletion deadline, charges a raw grant's finite parent disclosure pool with a conditional update for raw evidence (maintainer decision; ordinary downloads have no byte budget) and writes one audit row in the same transaction (ADR-330 D6). Raw artifacts additionally require their reviewed access facet. Browser and MCP use the same application path, with no second consent step for ordinary access.
