# ADR-299: TLS for protected named Go profile endpoints

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

Status: private implementation preparation; installed qualification pending.
Requirements: REQ-PRF-001/002/004. Extends ADR-285/287/296.

## Decision and boundary

The accepted profile contract includes administrator-approved TLS endpoints.
Extend the existing protected regional endpoint entry with optional
`tls: {serverName, rootsPEM}`. Roots are explicit public certificates, never a
credential. Require nonempty, canonical CERTIFICATE-only PEM, reject headers
and ignored junk, and cap input and canonical material at 8 KiB. This fixed
encoding/bound is an engineering choice, not a maintainer requirement.

Keep `GoEndpointTLS.Trust` as the existing `GoEndpointSource`: retain protected
endpoint source identity/provenance and bind the canonical public material in
`Trust.Digest`. Its ServerName and full Trust metadata remain in the canonical
endpoint definition and stable policy approval. Actual PEM travels separately
with the resolved plan and selected node work; it never enters approval/SQL
scopes. Recheck hash and definition consistency before enqueueing and before use.

The TLS work material is an immutable comparable value of strings and digest,
zero for legacy HTTP. No mutable byte slice/pointer aliases enter the existing
shallow-copy node queue. The node wraps the socket already opened in the exact
target Pod network namespace with `tls.Client`, explicit roots and ServerName,
HTTP/1.1 and the original caller/action deadline. Keep the existing post-dial
fit and cancellation checks. No ambient roots, insecure mode, new DNS lookup,
proxy, second connection, redirect, cleartext fallback or acquisition retry.
`Credential != nil` remains unsupported; no authentication material is delivered.

Manual and recurring policy endpoints retain the same definition digest.
Recurring resolution carries public Trust metadata/ServerName, not certificates
or a future Pod. Default HTTP encodings and digests stay unchanged when TLS is
absent. Keep the existing 64 KiB aggregate endpoint configuration and 256 KiB /
16-item node poll limits. Actual typed maximum/mixed-poll encoding tests must
pass before enabling the new configuration; do not widen either bound.

## Upgrade boundary

Generic `goProfile` availability and the upstream gadget version do not identify
Asservat's TLS wrapper. The existing node adapter report therefore gains optional
`profileTLS`, valid only with an available Go profile adapter. Old omitted flags
remain false and ordinary HTTP keeps working. Regional start and queue admission
refuse TLS for nodes without that capability; passive preview is not this proof.
There is no additional capability request or background process.

Upgrade connectors before collectors. Older connectors use a closed report
schema and reject the new field; newer connectors accept old reports and refuse
TLS on those nodes. There is no cleartext or legacy protocol fallback. Rollback
to HTTP removes the TLS endpoint configuration; restoring an old connector also
requires compatible old collectors. No persisted TLS state needs migration.

## Cost and qualification

This closes an existing required named-endpoint gap. It adds zero API requests,
RBAC, secrets, watches, services, Jobs or persistent/fallback states. The existing node report adds one optional boolean. One action
adds one TLS handshake and at most 8 KiB public certificate material on its
existing private work response. The application supplies its already enabled
TLS pprof listener. No new runtime dependency or tuning knob is introduced.

Split work into a shared pure value/certificate parser, protected configuration
and canonical planning, then node transport/runtime. Focused tests cover strict
PEM, source/digest/ServerName mismatch, HTTP byte compatibility, manual/policy
parity, wrong/untrusted/expired certificates, cancellation and original timeouts.
A later owned installed CPU workflow must establish exact netns/Pod, approval,
publication, native pprof and handshake refusal without GET/artifact/retry.
Component tests and this private branch do not qualify installed TLS or enable
collection. Credentials and broader S-05 remain separate required work.
