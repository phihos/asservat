# ADR-057 — Exact installation retention topology

> Superseded in part by ADR-328 (2026-11-13): the namespace/object UID and content-digest pins against a replaced or altered topology ConfigMap no longer apply. The hub reads the Helm-rendered topology ConfigMap by name under RBAC. Explicit hub/local source naming and the rule that callers cannot supply a source list remain.

Status: initial C-01/C-21 implementation profile under the maintainer's sustained continuation. It implements complete hub/local source selection; it does not change who can configure retention or authorize collection.

Use one immutable Kubernetes ConfigMap per target cluster for the initial source-topology read facet. Explicitly name the hub and local source, or explicitly record the absence of a separate local source. Helm renders the ConfigMap; runtime readers read it by name under RBAC. They cannot omit unavailable local sources or accept a caller's source list. No new state service or HTTP configuration API is added.

This avoids requiring another mutable configuration journal merely to describe a stable enrollment relationship. [Kubernetes immutability](https://kubernetes.io/docs/concepts/configuration/configmap/#immutable-configmaps) protects the data after creation against accidental edits. Source identity changes go through a Helm upgrade.

The chart generates the configuration; app maintainers get no additional task or prompt. Source identity migration requires preserving prior retention obligations and qualifying the replacement before activation. Ordinary retention policy changes remain mutable guarded CRDs. Restore composition remains required.

The component contract defines the bounded multi-cluster router, schema, freshness and current qualification status.
