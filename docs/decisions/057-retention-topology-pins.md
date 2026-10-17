# ADR-057 — Exact installation retention topology

Status: initial C-01/C-21 implementation profile under the maintainer's sustained continuation. It implements complete hub/local source selection; it does not change who can configure retention or authorize collection.

Use one immutable Kubernetes ConfigMap per target cluster for the initial source-topology read facet. Explicitly name the hub and local source, or explicitly record the absence of a separate local source. Independently accepted namespace/object/content pins bind these values to protected installation/enrollment configuration. Runtime readers cannot discover replacement pins, omit unavailable local sources or accept a caller's source list. No new state service or HTTP configuration API is added.

This avoids requiring another mutable configuration journal merely to describe a stable enrollment relationship. [Kubernetes immutability](https://kubernetes.io/docs/concepts/configuration/configmap/#immutable-configmaps) protects the data after creation; object UID and canonical content digest additionally bind the exact accepted object and initial values. Metadata changes remain possible and do not alter topology identity. Deletion/recreation requires requalification. Immutability alone does not authenticate original contents or prove cluster enrollment.

Installer automation must generate the configuration and protected pins together; app maintainers get no additional task or prompt. Source identity migration requires preserving prior retention obligations and qualifying the replacement before activation. Ordinary retention policy changes remain mutable guarded CRDs. Protected pin provisioning/migration and restore composition remain required; the current constructor inputs in integration tests are explicitly synthetic installer acceptance.

The [component contract](../architecture/retention-topology.md) defines the bounded multi-cluster router, schema, freshness and current qualification status.
