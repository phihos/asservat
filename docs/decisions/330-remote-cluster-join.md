# ADR-330 — Joining workload clusters with `mode: cluster`

Date: 2026-11-14. Status: accepted (implements slice 3 of the
[Helm-native plan](../reviews/helm-native-install-plan.md), "Remote regions").
Supersedes the console-issued bootstrap receipt and the `region.offer`,
`region.clusterID`, `region.peerID` and `region.bootstrapSecret` values of
`mode: cluster`, and the hub-side namespace/account UID part of the regional
executor pin.

## Problem

A second cluster installed with `mode: cluster` could not join a hub:

1. The hub published its regional offer only in `mode: combined`.
2. The console's `/fleet` issuance kept the one-use bootstrap record in
   OpenBao KV; nothing delivered it to an operator.
3. The offer named only in-cluster Service addresses, and the key service and
   object store clients verified the dialled host name.
4. The hub admitted context starts only from catalog entries the deleted
   `installer-cluster join` command wrote (guarded capability and work-trust
   sources, topology ConfigMaps, the remote namespace and account UIDs).
5. Key service and publisher had no retention topology for a joined cluster.
6. The hub-worker observed capacity only in the hub cluster (the ADR-197
   remote observation client was removed with the installer), so a remote
   workload never got a storage binding and every preview stopped at
   `facts/storage`.
7. The regional object-store principals were scoped to the hub cluster.
8. The executor pin took its image digest from the first stored offer, so any
   `helm upgrade` to a new image refused every context start, including the
   combined-mode connector's.

## Decision

The operator registers a cluster in the hub's values and copies one Secret:

```yaml
# hub values
clusters:
  - name: eu            # join Secret <name>-join-eu
    clusterID: <uuid>   # chosen by the operator (uuidgen)
remote:                 # how connectors reach the hub (TCP passthrough)
  federation: https://hub.example:9446
  owners: hub.example:9444
  keyService: https://hub.example:9447
  objectStore: https://hub.example:8333
```

- The connector peer ID is a name-based UUID of installation and cluster IDs,
  so every hub component derives it without shared state.
- hub-api issues each cluster's bootstrap through the existing audited
  pipeline with the installation as actor (the combined-mode path, ADR-193)
  and writes the join Secret `<name>-join-<cluster>` when it is missing: the
  cluster and peer IDs, the offer with the configured addresses, the
  cluster's two regional object-store capabilities and the record. A record
  is issued only when the Secret is (re)created, so deleting the Secret asks
  for a fresh five-minute record and an expired record spends no further
  bootstrap history. Later offer changes are written into the existing Secret.
- The workload cluster's release takes `region.joinSecret`; the connector
  reads IDs and offer from the mounted Secret (the Pod waits until it
  exists).
- The offer carries each endpoint's in-cluster server name; connectors dial
  the configured address and verify the Service name, as kubeconfig
  `tls-server-name` does. No serving certificate needs the external name, and
  no TLS-terminating proxy may sit in front of these mTLS listeners.
- hub-api derives each joined cluster's context-start entry from the stored
  offer and values (the combined-mode local entry, generalized). Key service,
  publisher and hub-api serve its retention topology in process from the hub
  retention source (ADR-195).
- The executor pin keeps the startup and image digests over Helm-known
  values. Namespace and account UIDs are not pinned (ADR-328: writers of the
  Asservat namespaces are trusted); the image digest is the release's current
  image.
- Capacity: each joined connector delivers its cluster's capacity
  observation every two seconds over the lifecycle channel (purpose
  `capacity`, as ADR-329 decision (c) delivers AccessBindings): the
  namespaces carrying a capacity key, only those labels, and their
  Deployments, StatefulSets and unowned Pods. The federation stores it under
  the presented cluster at its own admission time (migration 00163, one row
  per cluster). The hub-worker qualifies each joined cluster once (the
  existing write-once `qualify_capacity_cluster`) and serves the reconciler's
  reads of that cluster from the latest row while it is within the existing
  five-second capacity window.
- With bundled SeaweedFS the secrets hook generates
  `<name>-s3-regional-write-<cluster>` and `-regional-history-<cluster>`,
  scoped to the joined cluster's ID; with an external store the operator
  creates them.
- `federation.connector.profiles` must cover every connector; the chart
  refuses fewer. `fleet.maxClusters` and `fleet.maxActiveBootstraps` are
  raised to the hub-issued slots.

## Precedent

- kubeadm `join` and Karmada `karmadactl register` take a bootstrap token
  created on the control plane and copied to the member
  ([kubeadm token](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-token/),
  [Karmada pull mode](https://karmada.io/docs/userguide/clustermanager/cluster-registration/)).
- Open Cluster Management's `clusteradm join` uses a hub-issued bootstrap
  kubeconfig; the klusterlet reports status to the hub under its own
  identity ([OCM architecture](https://open-cluster-management.io/docs/concepts/architecture/)).
- Rancher's import manifest carries a registration token generated by the
  server ([Rancher import](https://ranchermanager.docs.rancher.com/how-to-guides/new-user-guides/kubernetes-clusters-in-rancher-setup/register-existing-clusters)).
- Argo CD names a cluster in a declarative Secret in its namespace
  ([declarative clusters](https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/#clusters)).

All register the member on the hub side by name and carry one credential to
the member; none needs hub access to the member's API, matching the accepted
outbound-only connector.

## Complexity gate

1. Every `mode: cluster` install failed to join (deterministic).
2. Not an accepted limitation: slice 3 of the maintainer's Helm-native plan.
3. Every multi-cluster deployment.
4. Above.
5. hub-api: `create` on Secrets in the release namespace (create cannot be
   limited by name), `get/update` on the join Secrets, `get` on the joined
   clusters' capability Secrets. Connector (`mode: cluster`): `list` on
   Deployments and StatefulSets. Federation login: one table; hub-worker
   capacity login: one table and one existing function. No new listener or
   credential type.
6. One degraded state: a stale capacity delivery (that cluster's capacity
   reads fail until the next delivery).
7. No configuration of the mechanism itself; `clusters` and `remote` describe
   the topology.
8. The connector must reach the four hub endpoints, which every joined
   function already needs.
9. Per joined cluster every two seconds: one LIST of namespaces plus three
   metadata LISTs per capacity namespace on the member's API server, one
   lifecycle conversation and one upsert on the hub, and one row read per
   reconcile step. Linear in clusters and capacity namespaces.
10. Upgrade adds a table; removing a `clusters` entry stops its join and
    capacity reads; downgrade drops the table.
11. Copying the bootstrap by hand from OpenBao, or documenting the gap, would
    leave capacity, topology, exposure and image upgrades broken.

## Known limits

- The bootstrap record is valid for five minutes from issuance; delete the
  hub's join Secret to get a fresh one before copying it.
- A failed first enrollment after the claim consumes the slot (unchanged
  behaviour); re-joining needs a new `clusterID`.
- The connector backing (`federation.connector`) is fixed at the first
  install: a cluster beyond `profiles` needs a reinstall.
- Remote captures need the joined cluster to run the hub's image digest.
- Capacity deliveries poll the member's API every two seconds; an informer
  would remove that cost and is not implemented.
