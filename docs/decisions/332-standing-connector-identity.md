# ADR-332 — Standing connector identity

Date: 2026-11-14. Status: accepted (maintainer goal: "a connector can start,
restart and enroll at any time after install without operator action; no
periodic polling to keep something fresh"; maintainer follow-up: connector
counts fixed at the first install are a no-go, clusters join without a
reinstall). Applies ADR-330 (state stays valid
until replaced; no expiry merely to force refresh) to the connector identity
backing of ADR-193. Resolves ADR-193's open risk "the connector backing's
`ValidUntil` needs a renewal plan" by removing the expiry instead of renewing
it.

## Problem

On a homelab installation (`mode: combined`, upgraded about four hours after
the first install) the connector never enrolled again after a restart; it
logged only `startup connector: waiting at identity (unavailable)`.

The hub-api writes the `<release>-regional-offer` ConfigMap once. Its connector
backing carried `Policy.ValidUntil` = first hub-api start +
`federation.connector.validSeconds` (3600 in the trial profile). The connector
refused its own identity document once that time passed
(`ConnectorIdentityConfiguration.Valid`), and SQL refused every process
admission and certificate after `connector_identity_root.valid_until`.

Nothing renews the backing. The designed renewal (a connector-driven backing
acceptance with successor tickets) has no producer, and it would have to run
periodically before expiry, with no recovery after it. The same finite design
has further walls that an installed system reaches later, because the
identity-lane cleanup, verifier, finalizer and process detachment duties are
not composed (`PublicRuntimeConnectorMaintenancePurposes` are "projected
nowhere"):

1. A cohort's retirement ticket admits processes only until
   `admission_until`, which had to precede the accepting record's original
   purge (acceptance + `retainedSeconds` − horizons). After it, the cohort can
   only be retired; the peer never enrolls again.
2. Every connector process row counts against the deployment's
   `RetainedProcesses` (8) until `detach_connector_identity` deletes it, which
   nothing calls. Eight process admissions (Pod restarts, or the hourly
   process rotation at `retainedSeconds` 4000) end enrollment.
3. Every identity-lane audit record (process enrollment, client and server
   certificate) charges the connector's account; only the uncomposed purge
   refunds it. Each enrollment charged three records on kind; with hourly
   process rotation and 30-minute certificate renewals a 96-record account
   lasts well under a day.
4. A process of a deleted Pod stays `serving` (only the same Pod's next
   process retires it), and `ServingSlots` (2) caps serving processes per
   peer: on kind the third connector Pod in a row was refused
   (`connector serving slots exhausted`).
5. `federation.connector.{accounts,profiles,sourceTransitions}` fixed, at the
   first install, how many connectors (one profile per cluster) and source
   changes the installation would ever accept; joining a cluster beyond
   `profiles` needed a reinstall (ADR-331).

## Research

The finite backing is agent-added prepayment of audit storage (ADR-126/153/
193). No external source describes a benefit for bounding a cluster agent's
identity by an installation-time deadline:

- [kubelet TLS bootstrapping](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/):
  a bootstrap token issues the first client certificate; the kubelet then
  rotates it by CSR before expiry, for as long as the node exists.
- [Open Cluster Management registration](https://open-cluster-management.io/docs/concepts/architecture/):
  the klusterlet registers with a bootstrap kubeconfig, then renews its hub
  client certificate by CSR for as long as the cluster is joined.
- [RFC 5280 §4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5)
  reserves `99991231235959Z` for "no well-defined expiration date"; that is
  the value used below.

ADR-330 D3 (standard identity) and D7 (no never-refunded charges, no
prepayment) already reject this machinery. The renewal alternative would add a
periodic timer, a hub-side backing producer and a recovery path for missed
renewals; that machinery has no precedent either.

## Decision

1. The connector backing is a standing configuration, valid until replaced.
   `buildConnectorBacking` sets `Policy.ValidUntil` to
   `fleetapp.ConnectorBackingStanding` (9999-12-31T23:59:59Z), independent of
   the setup time. `federation.connector.validSeconds` is removed from the
   chart, its schema and `InstallerConnectorSettings`;
   `ConnectorIdentityConfiguration.Valid` no longer compares it with now.
   `retainedSeconds` must still leave the regional shape a 1800-second process
   run (chart validation and `SupportsProcessLimits`).
   `federation.connector.{accounts,recordsPerAccount,profiles,sourceTransitions}`
   are removed as well, with the chart's "profiles must cover every
   connector" check; the backing carries fixed structural sizes
   (`fleetapp.ConnectorStanding*`) that size its accounting only.
2. Migration 00164 removes the finite walls, without adding renewal or
   cleanup machinery:
   - a retirement ticket's `admission_until` (the standing `ValidUntil`) is no
     longer bounded by the accepting record's purge (table check,
     `connector_retirement_ticket_valid`, Go `ConnectorRetirementTicket.Valid`);
   - process admission and serving no longer count earlier processes
     against `RetainedProcesses` or `ServingSlots`
     (`guard_connector_identity_process`); the one-pending and one-serving
     process per Pod indexes are unchanged;
   - connector profiles, source transitions and identity audit accounts are
     counted but not capped (root and pool checks,
     `guard_connector_identity_profile`, `lock_connector_process_current`,
     `lock_connector_credential_candidate`, `read_connector_activated_leaf`):
     a cluster's profile and account are created when it registers, keyed by
     its peer and cluster ID, and staging the same document again is
     idempotent;
   - identity-lane audit records are not capped per account
     (`guard_operation_audit`, `guard_operation_audit_pool`,
     `preserve_connector_ticket_backing`,
     `guard_connector_ticket_reservation`); other lanes keep their caps.
3. hub-api retries, in-process with the startup back-off (1 s doubling to
   30 s), a startup whose accepted owner configuration is not current yet
   (`postgres.OwnerConfigurationReadFailure`, for example
   `recovery-proof-interval`/`expired-interval` while an upgraded hub-worker
   waits for its scheduling Lease). Other startup failures still exit.

## Consequences

- A connector restarts and enrolls at any time after install. No timer,
  renewal or resend is added; process and certificate periods are unchanged.
- Identity-lane audit rows and expired process rows accumulate until the
  ADR-330 D3/D6 slices replace per-process enrollment and certificate audits
  with standard certificate rotation and audit rows with partition retention.
  Growth is a few rows per hour per connector.
- An installation created before this change keeps its stored finite backing
  in the offer ConfigMap and in SQL; the product is unreleased and has no
  migration for it (ADR-330 complexity gate item 10). Reinstall it.
- A standing cohort's retirement ticket has no admission end, so the
  expiry retirement (`originalAdmissionEnd`) never applies to it
  (`ConnectorRetirementTicket.Standing`); only an explicit retiring source
  retires it. The ticket's reservation no longer withholds any capacity:
  with the identity-lane caps removed it is an accounting row, consumed by
  that explicit retirement.
- Finite backings remain accepted by SQL (tests and older rows); only the
  shipped producer is standing.

## Complexity gate

1. Observed on an installed homelab; every installation hits it one hour after
   install. Not hypothetical.
2. Not accepted by the maintainer; the maintainer asked for the fix.
3. Typical deployments (every combined and cluster mode connector).
4. kubelet and OCM agents keep their identity until removed (above).
5. No new privileges, credentials or network access. The federation's
   in-process peer cache (64 peers) is unchanged.
6. Removes failure states; adds one bounded startup retry.
7. Removes five settings.
8. Standard PostgreSQL and Kubernetes behavior only.
9. No added API, watch or polling cost; a few audit rows per connector-hour.
10. Unreleased product; older installations reinstall.
11. A larger `validSeconds` only moves the wall; renewal machinery would add a
    timer and a recovery path.
