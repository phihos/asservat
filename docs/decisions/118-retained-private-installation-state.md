# ADR-118: Retain initial private material and read historical completion

Status: accepted continuation; SQL and native Kubernetes component qualification
passed. Full preparation/activation supervisor composition remains pending.

An interrupted preparation must not regenerate private bytes whose original
write or issuance may have succeeded. A successful installation must also remain
recognizable after its finite activation Pod and claim expire, without rerunning
activation or clearing later recovery/suspension.

The trusted bootstrap retains three independent random SQL password values in
one immutable private Secret, with original installation/request identity and an
independently pinned namespace/name/UID. The private reader verifies the current
administrator, original preparation guards/root and that immutable Secret. It
cannot create, rotate, adopt or replace material. No derivation seed, deterministic
key generation, provider reply or secret-payload hash enters public provenance.

A codec reconstructs the existing ADR-100 credential state from that material and
the original fifteen-minute UTC interval. Expiry does not prevent reconstruction
for exact lookup/retirement. The codec accepts a supplied interval; it is not its
durable acceptance or permission to provision. The continuing supervisor must
persist that binding before effects and preserve it through unknown results.
Provider-generated tokens/certificates retain their separate uncertain-result
protocols and cannot be inferred from this material.

Add a separately credentialed SELECT-only historical installation reader. It
requires current exact-scope operator protection before reading SQL and again
before returning, preserving the earliest original five-second deadline. Native
protection checks the original immutable startup inputs without requiring the
old Pod to be alive. The result distinguishes missing observation, prepared,
audited and historically activated, preserving exact claim/plan/audit identities.
It makes no mutation and supplies no current RecoveryReady, witness consumption,
pristine-database, writer-quiescence or credential-retirement proof. In particular,
a missing row cannot authorize a replacement attempt while another writer runs.
A historical activation can remain visible during a later recovery block.

This retains separate trust boundaries: Helm/bootstrap must preserve original
private material and release provenance; the setup runner owns its mutable public
journal; activation remains the existing one-use coordinator; retirement must
positively revoke external rights and reconcile its original writers. Ordinary
upgrades cannot rotate unresolved material. Uninstall retains unresolved material
and journals, and deleting a Kubernetes Secret never revokes provider credentials.

See [the continuation architecture](../architecture/initial-preparation-state.md)
for implemented scope, required composition and verification. This decision does
not enable Helm runtime services, replace consumed/expired claims or complete the
preparation/activation supervisor.
