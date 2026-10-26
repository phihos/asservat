# Current context-download authorization

C-03 now composes the ordinary access decision for the initial approved context artifact. `ContextDownloadAuthority` implements C-14's current download gate through domain values and consumer-owned ports. It has no SQL, Kubernetes, OIDC, object-store or transport dependency. Bootstrap supplies the separately scoped readers; missing readers deny access.

Before an initial or independent catalog lookup, resolve the authenticated credential, require the exact human/workload and OAuth client bound to the requested scope, and evaluate current target permissions, complete denies and download scopes. Then load a SELECT-only projection of the audited, verified catalog entry, original retained audience, current cutoff and the union of original/later-applied retention-policy identities. The SQL projection binds capture, artifact/attempt, exact pod/workload/namespace, ciphertext version and diagnostic purpose. It contains no native file content, checksum or filename. A generic custody record or unverified upload cannot produce this projection.

Evaluate ordinary rights against the original audience; newer ownership alone does not grant access to old evidence. Resolve current retained policy obligations using the trusted original classification, acquisition anchor and requested lifetime, preserving all prior policy relationships. Require a complete current retention proof, the original diagnostic purpose, and cutoffs no later than the already-effective dates. Acquisition may have ended: authorized download remains available until its separate evidence-access deadline.

A mandatory `DownloadEnvironmentReader` independently checks current recovery, processing restrictions, client disclosure and the exact regional store/relay path. Its finite result binds root, artifact/attempt/store, principal/client, region, policy revision and recovery epoch. The concrete [current environment composition](download-environment.md) joins independently guarded client/path policy with explicitly initialized SQL processing state and current recovery. It retains no permissive implementation or static region fallback. The [current SQL recovery reader and transaction fence](download-recovery.md) are now implemented and qualified with actual SQL/S3/native HTTPS tests. Protected source/backing installation, activation/restore reconciliation, business-history retirement and final runtime composition remain required before public use. Synthetic fixture acceptance of regional policy is not that producer.

After catalog/privacy/environment I/O, resolve identity and permissions again and re-evaluate the original audience. Changed identity policy or permission revision requires a fresh attempt; removed membership/rights or new denies refuse the download. The final lease is bounded by every original observation, current rights, effective retention, and at most five seconds from the initial check. A fresh later read cannot renew an earlier decision. The content-minimized decision digest records this provenance without retaining the credential or native evidence.

For one original content response, [ADR-220](../decisions/220-response-owned-download-permissions.md)
adds a separate ordinary-entitlement owner. A successful complete construction
stores copied identity claims, exact scope/audience, permission revision and
contributing assignments, with a cutoff at the original pre-I/O start plus 30
seconds. It does not retain a reusable complete authority or change projection
freshness. Each short batch still authenticates the same principal/client and
reads current catalog, retention and environment facts. Changed policy/groups/
scopes require fresh target eligibility before catalog access; mismatched audience
or version refuses. At the cutoff, reconstruct before more output. Failure in
refresh or later safety reads closes the owner, and Close cancels/joins blocked
work. New GETs/preparation construct independently. Every emitted authority stays
within five seconds and all original caller/session/access/observation limits.
Known SQL permission changes may deny earlier; 30 seconds is reconstruction
cadence, not a revocation guarantee. The concrete native response consumes the
coordinator's exact short authority privately rather than reconstructing it.

[ADR-233](../decisions/233-recipient-native-download.md) adds the concrete-share branch of
[ADR-232](../decisions/232-concrete-evidence-share.md): only when ordinary target eligibility
refuses, the caller's own shares of exactly the scope's artifact and version are read before the
catalog lookup (no admitting share, no lookup); after the catalog read the share must also name
the artifact's case, its pinned manager must be in the original audience, and the final check
re-reads the share. A share-admitted response entitlement uses the same 30-second reconstruction,
bounded by the share's expiry, and the decision digest binds the share ID and revision. Current
denies win, `evidence:download` is required, and sessions are charged to the workload's existing
allocation.

The SQL [retention effect checks](retention-effects.md), batch accounting and immutable encrypted audit still precede every disclosure. The authorizer alone does not emit bytes or reserve a session. Raw artifacts require their separately reviewed access facet; unsupported input cannot be relabeled as approved context. Browser and MCP will use the same application path, without a second consent step for ordinary access.

Unit/race tests pass in `test/results/download-authority-unit.log`: revoked membership, denies arriving during I/O, changed client/identity policy, unrelated artifact/version/store, purpose changes, closed/lengthened retention and expired original observations all refuse access. The real SQL/S3/native-HTTPS suite passed with this authorizer and its actual catalog/permission/retained-policy adapters (`test/results/download-authority-integration.log`, 52.904 seconds; unchanged source and complete cleanup). Go/race/import/SQL/spec/architecture/design gates also passed in `test/results/download-authority-gates.log`. IdP claims, installation observations and regional/recovery qualification remain explicit fixture inputs. Public ingress/relay, complete raw/share authority and the developer UI/MCP workflow are still pending.

The [ADR-220 component archive](../../test/results/resumed-c62e02ac-response-permission-cadence/README.md)
records genuine RED and passing affected package race checks for the response
owner and private native handoff. Its real SQL suspension assertion is compiled
but unrun. This does not qualify sustained installed streaming or other artifact
classes; older qualification paragraphs above retain their original scope.
