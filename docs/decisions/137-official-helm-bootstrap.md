# ADR-137 — Package the fixed initial installer with Helm

Status: accepted; packaged native Helm/private-registry component run passes;
earlier unexplained hook failure and installed runtime qualification remain open.

## Decision

Helm may opt into the existing four-command initial installer while public
runtime remains disabled. The trusted administrator supplies ordinary static
settings, the original verified image digest and explicit upstream Secret
references. The product derives installation/request IDs, SQL manager/OIDs,
Kubernetes UIDs, native guards and progress; Helm never owns those mutable or
private values.

The chart uses one Restricted Pod with three sequential init containers and
final retirement, an 8 MiB tmpfs and the existing product-owned private child.
It runs as a post-install/post-upgrade hook with only hook-succeeded deletion.
A fixed name preserves uncertain/live/failed orchestration. There is no default
before-hook replacement, retrying Job, force operation or automatic rollback.
An administrator-facing `installer-resume` command may remove only an exact
positively terminal original Pod after bounded public-input/template/UID/RV
checks. It cannot approve recovery or reset product progress.

Immutable revision-named public ConfigMaps bind both complete public inputs.
A retained hook always refers to its original revision. Keep those snapshots
until positive unreferenced cleanup is qualified; this is not Helm ownership of
product history. Preserve the original bootstrap image separately from future
runtime images. A new bundle is not an initial-install replay.

Private input projections are optional at the volume layer so completed replay
starts without setup files; active phases still require their specific input.
Public PEM normalization and a single current token audience hint precede private
effects, without conferring authority. Exact API authentication and native guard
proof remain mandatory. The local resume CLI uses standard kubeconfig/current
context resolution, never ambient in-cluster credentials.

An optional closed `dockerconfigjson/v1` capability reuses the exact journaled
activation provider Secret for image pulls. It contains the original seven
mounted files plus one bounded Docker auth key, while the activation process
still mounts seven files only. Kubelet consumes the additional key. The original
UID and positive deletion lifecycle cover the copy. Omission preserves previous
wire/Pod/Secret behavior. Operator originals, registry revocation and caches are
outside managed-copy deletion.

A read-only CLI prints exact public OpenBao policy/token-role prerequisites from
the existing policy builder. It never loads root credentials or applies them.
No dependency installation or new authority framework is introduced.

## Consequences and qualification

See [Helm bootstrap](../architecture/helm-bootstrap.md) for the boundaries and
[operator instructions](../installation/helm.md). The underlying ADR-133 v3
four-command chain is native-qualified separately. This increment requires an
actual packaged Helm run with empty SQL, original activation and retirement,
setup-free replay, terminal-only resume, and authenticated cold exact-image
pulls on two owned nodes. Offline render/unit checks alone do not qualify that
composition. Hook success establishes an initial checkpoint, not a usable
investigation platform or restart/restore approval.
