# Installation namespace staging

[ADR-101](../decisions/101-installation-namespace-staging.md) fills the preparation
boundary before [the final installer workload guard](initial-installer.md) can
know actual Pod/account UIDs. `InitialNamespaceAdministration` is an inert private
plan. `InitialNamespaceAdmission` builds a namespaced fail-closed native policy
and Deny binding for one explicit namespace; system/default namespaces, invalid
names, duplicate administrators and colliding probe/input names are rejected.

`InitialNamespaceCreator` now performs the ordered policy, binding and fresh
namespace creates. It authenticates the configured administrator online before
each mutation, refuses an existing namespace before creating any guard and sends
each POST once with strict field validation. Its installation/request stamp binds
the intended preparation, while actual API UIDs identify acknowledged effects.
A failed or unknown reply stops the sequence and returns already acknowledged
pins; it does not replay, adopt a conflicting object, invent the missing identity
or delete uncertain state. Response decoding starts from empty objects, so
omitted API fields cannot inherit the intended labels/stamp from the request.

`Resume` is read-only: it requires the original complete namespace/guard pins,
compares exact current native specifications before and after the namespace
read, and requires the same installation/request stamp and Restricted label.
It cannot repair missing objects or resume partial creation on its own. The
[preparation journal](initial-preparation.md) now retains ordered subsequent
create intent and receipts. The supervisor still must retain the original root
identities and establish clean setup history before future identities or
credentials exist.
`InitialNamespaceProtection` requires the actual UID and expected
policy/binding identities, compares exact native specifications, independently
checks non-administrator/RBAC-qualified enforcement, then rereads the same guard.
The original observation lasts no more than five seconds and respects a shorter
caller deadline. A removed/replaced/changed guard or namespace is unavailable.

The two public ConfigMap names serve different purposes:

| Object | Non-administrator dry-run UPDATE | Persisted UPDATE |
| --- | --- | --- |
| Preparation probe marker | Denied by staging policy | Denied |
| Final startup inputs | Allowed by staging only; final guard must independently deny | Denied |

The exception still requires Kubernetes RBAC. It applies only to the exact
startup-input name, core ConfigMap resource, empty subresource, UPDATE and an
explicit true dry-run flag. It permits no secret read/write, token minting,
arbitrary dry-run resource or actual workload execution. Explicit administrators
perform staging mutations. Normal runtime controllers remain outside this
temporary policy's allowances until handover to the final workload guard.

The complete supervisor must prove staging before establishing future installer
identities, create and retain the original gated Pod, install final guards and
inputs, qualify their independent probes, provision finite credentials, remove
only the retained staging binding and finally release only the original gate.
It must persist its exact progress across uncertain API replies and retain both
old/new protection through handover. No helper may use guard success as SQL
activation, historical compromise repair or approval to discard unknown state.

Actual checks and limitations belong to [implementation progress](../implementation-progress.md).
The native test uses the product creator and read-only resumption, then
fixture-driven probe provisioning with synthetic markers/credentials. Read isolation still comes from RBAC; native admission
cannot protect GET requests. Other application namespaces are not affected.
