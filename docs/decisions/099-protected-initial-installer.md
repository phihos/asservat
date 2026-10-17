# ADR-099 — Protected initial-installer execution

Status: accepted engineering refinement under the maintainer's implementation
continuation. Qualification is recorded in [progress](../implementation-progress.md).

## Decision

Add private `asservat initial-install`, separate from migrations and ordinary
services. It consumes one fixed installation-owned projection and invokes
ADR-098; it cannot create an installation witness, modify schemas, recover a
database or start the public platform. A one-minute process operation includes
bounded startup and the existing thirty-second activation coordinator. Failure
or cancellation is a nonzero exit, with no automatic retry or replacement Pod.

Build a single Restricted Pod with `restartPolicy: Never` and an initial
[scheduling gate](https://kubernetes.io/docs/concepts/scheduling-eviction/pod-scheduling-readiness/).
The trusted provisioner retains its UID and server-defaulted specification,
protects the dedicated namespace, installs immutable inputs and credentials,
qualifies the native guard and only then removes the gate. The specification
digest excludes only scheduler node assignment and the removable gate. It
includes every container, image, command, volume and security setting.

The installer uses a kubelet-projected, Pod-bound writer token. Online
SelfSubjectReview must report the exact account UID and Pod name/UID; no decoded
JWT, unbound token or account-name match substitutes. Kubernetes documents the
[bound token identity and online validity checks](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/).
A separate finite probe principal supplies RBAC-permitted dry-run denials. It
cannot be a namespace administrator; the writer cannot be one either. The
probe's provisioner-issued token is short-lived and bound to a separately
revocable Secret. It is not a perpetual service-account token. Only installation
provisioning can issue or replace it.

Kubernetes [caches successful token authentication](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/kubeapiserver/options/authentication.go), with a ten-second default in the researched reference version. An accepted SelfSubjectReview therefore does not prove that the bound account or object still exists at that instant. Independently read the live writer/probe accounts and the exact Pod inside the original five-second interval. Credential retirement confirms actual rejection; deleting its backing Secret alone is not an instantaneous revocation guarantee. Do not change the API server's cache to make the test pass.

Native namespace admission permits only explicit administrators, the exact
writer's witness update, the exact probe's nonpersistent witness/fleet tests,
the pinned Pod's scheduler/status/removal operations, its kubelet token requests,
and ordinary events. No runtime workload creation, exec, token minting, source
modification or credential read permission is granted. Admission does not govern
GET: scoped RBAC and a clean installation protect Secret reads separately.

Current protection and exact live Pod specification bound every witness read
and consume, including the final pre-activation read. Retain the original
five-second protection deadline through witness/source reads and SQL locks.
Missing protection, Pod replacement/deletion or a different account blocks
activation. This proves current state; trusted provisioning must still establish
the clean installation history before any credentials or executable are exposed.

The immutable attempt's plan digest is computed from the closed typed public
startup document, including all provider endpoints, public roots and pins.
Credentials use fixed separate files; their rotation cannot select new SQL
roles. Three distinct purpose-scoped SQL logins and separate audit wrap/unwrap
tokens reuse the existing verified TLS, confined file reads and envelope audit.
No new cryptographic implementation or dependency is introduced.

## Remaining composition

The generated objects are inert and the loader is private. Production provisioning
must retain exact inputs, prove a clean namespace, create/retire temporary provider
credentials, handle partial installation without adopting foreign state and
complete local-key pre-activation audit. Do not enable the Helm runtime until
that lifecycle is qualified. Restart/restore, independent checkpoints and old
primary fencing remain separate; this executable is never their substitute.
