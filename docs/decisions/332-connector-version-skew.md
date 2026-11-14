# ADR-332 — Hub and connector version skew

Date: 2026-11-14. Status: accepted (maintainer decision: "the same image
digest [on hub and workload clusters] is an absolute no-go"). Supersedes the
executor pin of [ADR-331](331-remote-cluster-join.md) ("The executor pin keeps
the startup and image digests") and of ADR-196, and the "Remote captures need
the joined cluster to run the hub's image digest" known limit.

## Problem

The hub refused every context start unless the connector's executor reported
exactly the hub's image digest and a startup digest computed over that image
(`ContextStartExecutorPin`). Execution, publication and live-manual checks
again required the executor's image digest to equal the capability's collector
digest. A workload cluster therefore had to be upgraded in lockstep with the
hub, and operators had to install the hub's digest in every cluster
(`--set image.digest=<hub digest>`). Upgrading the hub refused all remote
captures until every cluster had been upgraded.

The pin defended against nothing: ADR-328 makes the Asservat namespaces
administrator-only, and the connector is authenticated by its cluster
certificate (mutual TLS) and its registered process identity. Whoever can
change the connector's image can change its configuration and credentials.

In addition the hub↔connector decoders were closed (unknown fields refused,
canonical re-encoding required), so even with the pin removed a hub one
release newer that added a field would break every older connector.

## Decision

1. **No digest gate.** Image and startup digests are not compared between hub,
   connector, collector or download worker for admission or authorization.
   They remain provenance: the connector reports them in its context-start
   Hello, the execution record stores the executor's image digest and the
   outcome audit its startup digest. The capability's collector digest names
   the hub release that compiled the recipe and projection; the manifest
   records it as before.
   Removed: `ContextStartExecutorPin` and the catalog's `executor` section;
   the executor-image = capability-image checks in API context execution,
   reference verification, completed-execution publication, live manual
   inspection; the tautological image field of the connector observation pin.
2. **Protocol version and capabilities.** The connector's context-start Hello
   carries `protocol` (`contracts.ConnectorProtocolMajor`, now 1) and
   `capabilities`: every operation (`operation/<method>`), pre-work query
   (`query/<method>`) and `history` its release answers. The hub refuses a
   Hello of another major (refusal stage `connector-protocol`). Within a major
   it sends only announced requests; an unannounced one is refused before
   anything is sent with `connector too old for <capability>`
   (`ConnectorTooOldError`, diagnostic step `connector-too-old/<capability>`).
   A refused query leaves the standby waiting; a refused operation fails only
   that work. Capability names are never reused with another meaning; a
   change that an older connector can neither ignore nor refuse per request
   raises the major.
3. **Tolerant decoders.** The context-start frames (Hello, work, operations,
   replies, results, receipts, source frames, history and source work), the
   cluster-observation frames, the lifecycle channel and the connector's
   reading of the hub's offer ignore unknown fields. Signed work keeps its
   signature over the received bytes; its known fields must still be this
   release's canonical profile. A newer hub sends a new field only together
   with a capability the connector announced.
4. **Skew policy.** A connector (with its node collectors, which share its
   release) may be one minor release older or newer than the hub, with the
   same protocol major. During 0.x development the protocol major is the
   compatibility boundary. Each workload cluster's release uses its own chart
   version's image; upgrade the hub first, then the clusters.

## Precedent

- Kubernetes' [version skew policy](https://kubernetes.io/releases/version-skew-policy/):
  kubelet may be up to three minor versions older than kube-apiserver and
  must not be newer; components negotiate API features instead of requiring
  equal builds. We start narrower (±1 minor) because the connector channel is
  younger and less tested.
- Protocol Buffers [ignore unknown fields](https://protobuf.dev/programming-guides/proto3/#unknowns)
  so older and newer binaries interoperate; JSON decoders here do the same.
- The Docker Engine API [negotiates a version](https://docs.docker.com/reference/api/engine/#api-version-and-backward-compatibility)
  between client and daemon rather than requiring matching releases.

No comparable multi-cluster agent (Open Cluster Management klusterlet,
Karmada agent, Rancher cattle-cluster-agent) requires its agent image digest
to equal the hub's.

## Complexity gate

1. Every hub upgrade refused all remote captures until each cluster was
   upgraded (deterministic); the maintainer called equal digests a no-go.
2. Not an accepted limitation; ADR-331 listed it as a known limit.
3. Every multi-cluster deployment.
4. Above.
5. None added; a check is removed.
6. One refusal state per request (`connector too old`), replacing a refusal
   of all requests.
7. None.
8. None.
9. About 1.5 KiB more per Hello; a map lookup per operation.
10. Upgrade order hub first; rollback of either side within the window works;
    both sides of this change speak protocol 1. Connectors built before this
    change send no protocol and are refused (`connector-protocol`): upgrade
    them once.
11. Documenting lockstep upgrades is what the maintainer rejected.

## Known limits

- The window is enforced by capabilities, not by comparing release numbers:
  a connector further back than one minor works as long as it announces what
  the hub needs, but only ±1 minor is supported and tested.
- The manifest's collector digest names the hub's release, not the executing
  connector's image, which is in the execution record and outcome audit.
- The connector does not yet check the hub's protocol; a newer major hub
  refuses the connector's Hello.

## Verification

- Unit: `TestOlderConnectorRunsSupportedWorkAndRefusesMissingOperation`,
  `TestUnannouncedQueryIsRefusedWithoutIO`, `TestHandlerChecksProtocolMajorOnly`,
  `TestAnnouncedCapabilitiesMatchEveryMethod`, `TestNewerPeerFieldsAreIgnored`
  (internal/transport/contextstart); the API context execution fixture runs
  with an executor image that differs from the capability's.
- kind (2026-11-14, combined mode, one disposable cluster): hub components on
  image A, connector Deployment and its config on image B (same binary, a
  different image digest); `TestHelmNativeKindJourney` passed (regional
  pod-status capture collected, verified, published and downloaded). No
  mixed-protocol (older binary) installed run was made.
