# ADR-097 — One-use installation witness

Status: accepted engineering refinement of REQ-DEP-005 and REQ-DB-005. The
witness component is implemented; the initial/restore activation coordinator
and its production installer are not.

Subsequent [ADR-098](098-first-installation-activation.md) implements the separate
first-installation SQL/audit coordinator. Production provisioning and restore
activation remain unfinished; the witness alone still grants no authority.

## Problem

Empty or restored PostgreSQL state cannot establish that an installation has
never activated. ADR-096 blocks a changed database incarnation, but an ordinary
startup hook must not interpret missing SQL rows as permission to activate again.

## Decision

Retain one protected Kubernetes ConfigMap outside PostgreSQL, with independently
pinned installation, issuer epoch, cluster, namespace UID, object UID and writer
ServiceAccount UID. Its private `installation-witness/v1` record starts with a
null claim. The narrow consumer can update that exact existing object once with
an immutable activation-attempt claim and `immutable: true`, using its original
resourceVersion and UID. It has no create, delete or reset operation.

Kubernetes [immutable ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/#immutable-configmaps)
reject later data changes and reversal of immutability. Administrators can still
delete/recreate objects; the pinned UID must therefore remain authoritative.
Missing or replaced state requires recovery, never automatic fresh creation.
The installer must retain this identity and its pins across upgrades and ordinary
uninstall until qualified retirement. The current helper only produces initial
data; it does not provision or recover a witness.

Before consuming, verify the actual writer username/UID and current named UPDATE
permission, plus independently observed admission enforcement. Recheck the pinned
policy/binding and namespace after I/O. Claims bind a database incarnation/schema,
fleet-source revision and plan digest, and expire within five minutes. Observations
last at most five seconds and preserve original deadlines after blocking work.
Consumed expired claims remain readable for diagnostics, not executable authority.

An uncertain write is never refunded or blindly retried. Independently read the
object back; only the exact persisted claim can recover the same attempt. A
different contender loses. Even expiry immediately after persistence leaves the
witness consumed. Witness consumption alone neither proves a pristine database
nor supplies encrypted audit, recovery acceptance or SQL activation authority.

## Integration boundaries

The future coordinator must establish protected installation identity, atomically
check eligible SQL state, durably audit activation and check the current database,
source and plan before activation. It must preserve later recovery blocks and
uncertain spend. The witness is one prerequisite, not the complete protocol. SQL
locking/role design and first-activation audit bootstrap remain unfinished.

Restore still requires independently retained revocation/deletion/accounting
checkpoints and old-primary fencing. This ConfigMap is outside SQL but is not
independent of a rollback of the entire Kubernetes control plane. Backup and
recovery qualification must address that failure model. Qualified lossless
restart activation should be automatic; no routine developer approval is added.

C-04 owns the read/consume ports and domain values; C-21 implements their native
Kubernetes boundary. No public API, CRD, SQL migration, dependency or runnable
installer is added. See the [component contract](../architecture/installation-witness.md)
and [measured verification](../implementation-progress.md). Native tests qualify
the protected record with actual API tokens, not a protected Pod-bound installer
or a complete installation/restore workflow.
