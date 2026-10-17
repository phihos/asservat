# ADR-088 — Owner startup readiness and runtime composition

Date: 2026-10-10. Status: selected for implementation under continuing maintainer authorization. Requirements: REQ-FED-001, REQ-DEP-003, REQ-DLD-003, REQ-CAP-003; part of TASK-02 and S-01/S-02.

## Problem

Current owner peer authentication requires an activated identity and a Ready Kubernetes route. Using that check as the Pod readiness prerequisite would make first startup circular. Successful credential enrollment alone is also insufficient: it cannot retain readiness indefinitely after configuration, Pod protection or registration becomes unavailable. Independent credential, listener and forwarding lifetimes must close together.

## Decision

Add a separate C-04 `OwnerStartupReadiness` check. It validates the exact independently pinned pool/process, both owned credential purposes, actual cryptographic verification under pinned/current roots, current activated registration, and the existing pre-Ready Pod/token/CSR/protection proof. Repeat registry/crypto checks, require the same accepted configuration across purposes and recheck both owned keys at completion. Retain all original proof/registration/parent/certificate deadlines under one five-second aggregate limit. Readiness neither signs nor acknowledges audit, changes recovery, looks up a Ready endpoint or grants request authority.

The C-21 credential adapter supplies copied public CSR/certificate snapshots only after enrollment and verifies the currently owned identity. Caller mutation cannot change its CSR. Closing or changing a key during the other purpose's checks invalidates the result. No private key, token or new wire value is exposed.

Add a concrete `bootstrap.OwnerRuntime` composition using independently accepted installation dependencies. Validate the exact pool, Pod and configuration-source UID; read current unsuspended accepted configuration and copy its roots. Disable this process's core dumps before creating keys. Generate a fresh random UUID process epoch and independent server/client keys, construct the existing request receiver and live forwarder, and bind the same registry, proof, protection and route sources throughout.

`Run` owns one TCP listener on the accepted private port. It enrolls/supervises the pair before serving, checks readiness serially once per second after each check completes, and exposes an expiring in-process scheduling hint. Failed observations clear that hint; a stalled observation cannot extend its last deadline. Successful observation can recover readiness without process restart. New forwarded work requires the hint and still passes all current peer/locator/worker checks. Incoming private requests retain their existing full current authentication. Readiness never substitutes for those gates.

Cancellation, credential-supervisor failure or listener termination stops the composition. Close keys, forwarding and sockets, clear readiness and join started supervisor/listener/readiness work with a six-second shutdown ceiling. A noncooperative dependency returns failure; it does not justify an unbounded wait or a successful-cleanup claim. No new request survives the original root cancellation. Existing owner/worker delivery deadlines remain unchanged.

## Scope and tradeoffs

This is the owner subsystem's concrete composition, not a complete `hub-api` command or installation. Other hub dependencies must participate in whole-Pod readiness. No new anonymous health listener, public permission endpoint, SQL migration, secret file format, chart switch or user approval is introduced. The request-owner factory only composes existing process-local routing; it is not a callback from a worker or a source of new authority.

The deployment loader still must construct protected Kubernetes/API clients, separate provider/SQL roles, rotating projected token readers, continuously reconciled configuration/recovery and the installer acceptance path. An installation starting RecoveryBlocked cannot be made available by this runtime. Do not replace those facts with fixture values or silently enable the chart.

Checking both purpose proofs adds Kubernetes/SQL work. The loop is serial with a fixed delay and at most one in-flight five-second check per runtime. Native proof correctness and deployment-wide API/provider load are separate qualifications; no throughput or overhead percentage is assumed. A future shared-observation optimization must preserve independent key/registration checks and original deadlines.

## Validation

Use real cryptography and TLS with explicit synthetic authority ports for lifecycle, readiness loss/recovery, protected source mismatch, fresh epochs, stale/rolled-back readiness, key changes during checks, parent expiry, shutdown during enrollment and listener failure. Native integration additionally must show startup readiness succeeds before Kubernetes Ready while ordinary peer admission still denies it, and fails after root removal or Pod deletion. Preserve actual source/cleanup reports in the implementation record. Native in-Pod composition, routing and the complete investigation workflow remain required.
