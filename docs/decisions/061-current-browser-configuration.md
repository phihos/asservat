# ADR-061 — Current protected browser configuration

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

> Superseded in part by ADR-328 (2026-11-13): the pinned ConfigMap UID, source-replacement rejection and bootstrap qualification of the protected namespace no longer apply. The hub reads the Helm-rendered browser-settings ConfigMap by name under RBAC. Finite ceilings, irreversible shortening of existing sessions, never-reused epochs and sign-out during outages remain.

Date: 2026-10-10. Status: implementation refinement of ADR-060; production bootstrap and recovery qualification remain open.

Browser ingress must not use a permanently enabled SQL root created by installation scripts. Administrator-owned Kubernetes configuration remains the source of session settings. A Helm-rendered ConfigMap, read by name under RBAC, carries the closed [browser-settings contract](../../specs/contracts/browser-settings.schema.json), with no credentials, independently of the existing identity/group policy. A separate observer projects a complete read into SQL for at most five seconds measured from the source read. Failed observations fence the preceding projection; an older failure cannot disable a newer successful observation. Ingress cannot renew or modify this configuration.

The projection records revision/digest, installation session root, epoch, issuer, client and browser origin. Changing issuer, client or origin requires a new epoch. Previously used epochs cannot return. Migration 00021 disables unqualified roots; first qualification removes their old login challenges and sessions. This migrates no credentials into trusted authority.

Finite administrator ceilings cover pending logins, retained sessions, logout receipts and absolute session lifetime. Lowering the lifetime shortens every existing session from its original creation time. Raising it permits longer new sessions but cannot extend a retained session. The observer performs shortening in the same bounded transaction as accepting the new maximum. A timeout rolls back the configuration update; the previous five-second lease still expires. Large-installation throughput qualification remains required.

Session identity, login and refresh require current configuration before and after blocking SQL work. Local CSRF-only lookup and revocation, signed provider logout and bounded expired-state cleanup remain possible during suspension or a settings-source outage, within their exact epoch and existing session deadlines. These paths return no identity or evidence and create no session authority. This keeps sign-out usable during an incident.

SQL carries that original configuration deadline in a transient session
observation. Current settings/session reads validate it before and after blocking
work; callback session creation retains its original settings handoff.
[ADR-300](300-browser-evidence-request-lifetime.md) corrects the later request
identity handoff: its lifetime follows verified token/key/group/policy bounds,
the fixed current session expiry and the original operation window, while every
subsequent session read still needs fresh current settings. Scheduling metadata
does not replace identity expiry. CSRF-only reads carry no identity observation.
This adds no stored lease or migration and extends neither a session nor a
configuration observation.

Installation configures provider/client endpoints, private credentials and the restoration epoch before opening production ingress. Current settings reads are not evidence of a safe database restore. No directory-reader account, offline user token, alternate permission-management HTTP API or new service dependency is introduced. See [browser sessions](../architecture/browser-sessions.md) for the integration evidence and remaining composition.
