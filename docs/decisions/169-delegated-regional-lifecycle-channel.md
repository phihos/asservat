# ADR-169 — Delegated regional lifecycle channel

Date: 2026-10-14. Status: accepted design (follows ADR-168); channel, both adapters and a two-cluster native fixture qualified; production process composition pending.
Requirements: REQ-FED-001/002; TASK-03 / TASK-11.

## Context

[ADR-153](153-operation-owned-connector-enrollment.md) drives connector process
admission and leaf signing through four phases (Initial, BeforeEffect,
BeforeActivation, Final). Each phase needs a native observation: Pod-token
review and the live Pod/ReplicaSet/Deployment chain, source and guard. The
existing `kubernetes.ConnectorLifecycleReader` performs those reads against the
workload cluster's API. With outbound-only connectivity
([ADR-168](168-rotating-cluster-enrollment-credential.md)) the hub has no such
API access. The effects themselves (SQL spend, encrypted audit, signing,
activation) are hub-only duties and never move to the region.

## Decision

The regional process produces phase observations in its own cluster, and the
hub consumes them as **delegated regional proof** over one connection.

1. The connector opens one TLS 1.3 HTTP/2 connection to the hub's private
   listener, with server authentication only, and sends one full-duplex POST.
2. Its first frame carries the exporter-bound ADR-168 presentation (admission or
   renewal), both CSRs and the operation purpose. The hub verifies the
   presentation before any other work; the CSR digests must equal the presented
   ones.
3. The hub runs the unchanged ADR-153 lifecycle with an operation reader whose
   `Read(phase)` writes one phase-request frame and waits for exactly one
   observation frame on the same stream. The connector answers by running the
   existing Kubernetes lifecycle reader locally for that phase.
4. The hub writes the final result (issued leaves or a closed failure label) and
   ends the stream.

5. The hub selects the duties of exactly the presented peer
   (`connectorlifecycle.Runners`). An unknown peer is an error and never falls
   back to another profile.
6. An enrollment conversation first asks the region for its protected source
   configuration and runs the unchanged source-staging duty with it. Staging
   only creates a candidate, a fence or a resume of the exact accepted profile;
   acceptance stays a separate audited hub step.
7. A third purpose, `registration`, carries a renewal presentation for the
   process plus one of its leaves. The hub runs the SQL activated-leaf registry
   with the region's delegated source reads and returns the record only if it
   names exactly that process and leaf. The regional process therefore needs no
   hub SQL credential for its leaf registry check either.

The TLS session binds every later frame to the presented credential, so no
per-frame signature is needed. Each observation still passes the domain's
`ConnectorLifecycleObservation.Valid` checks and original deadlines on the hub.
Frames are bounded in count (at most eight region frames: a configuration,
one begin acknowledgement and four phases for enrollment, two source values for
registration) and size. There is no
retry, and the conversation is one-shot: a broken stream leaves any spent claim
uncertain.

## Trust consequence

Unlike hub-side TokenReview, the hub cannot independently confirm a delegated
observation. It trusts the holder of that cluster's credential Secret, which is
the trade-off ADR-168 accepted. A compromised Secret lets its holder obtain leaves
for that profile until rotation or fork fencing, never for another cluster. It
never obtains evidence or key access without the separate ADR-126/153 and
download checks. The installer limits Secret access to the connector account.

## Implementation status

`internal/transport/connectorlifecycle` holds the frames, the hub handler and
the regional client. The handler requires HTTP/2 and TLS 1.3 and binds the
exporter-bound presentation to the exact CSR keys, process and profile before
any lifecycle work. Its per-conversation reader accepts one operation and only
observations for the exact begun binding and phase. Frames are bounded in size
and count, and every receive has a mandatory read deadline.
`TestDelegatedLifecycleChannelOverRealHTTP2` passes over real TLS 1.3/h2. It
drives a scripted ADR-153 runner through begin, four phases and close, and
refuses a presentation bound to other CSR keys and an observation for another
binding.

`connectorlifecycle.Runners` runs copies of the unchanged
`ConnectorLifecycleEnrollment`/`Renewal` runners whose native reader is the
conversation's delegated reader. `bootstrap.RegionalLifecycle` implements the
`mtls.ConnectorProcessAdmitter`/`ConnectorProcessIssuer` ports for
`ConnectorProcessCredentials`. Each call is one conversation. The rotator's
`Signer` fills the current Secret generation and profile itself, refuses while a
rotation is pending, and the adapter refuses a process bound to another
peer/cluster/installation before connecting.
`TestRegionalLifecyclePresentsCurrentGenerationOverRealHTTP2` passes with a
real Ed25519 Secret seed, real identity-free P-256 CSRs and
`mtls.EnrollmentProof`, and a hub presenter that verifies the exporter-bound
signature.

### Native qualification

`TestDirectHolderObservationWithRealKubernetes` now composes ADR-169 in its two
owned clusters. The owner Pod serves the channel with the real ADR-153 runners,
SQL, encrypted audit and the ADR-168 SQL store. The regional Pod holds only its
cluster credential Secret (get/update on that one name) and in-cluster readers;
it no longer receives the connector journal, acknowledgement, read or recovery
SQL credentials. Run 4 passed all six required tests with empty cleanup and
unchanged sources ([result](../../test/results/adr169-direct-native-4/result.json)).
The provider issuer and setup roots remain explicit fixture authority.

Runs 1–3 failed and are retained:
[1](../../test/results/adr169-direct-native-1/result.json) let the regional Pod
start before the owner listener existed (the harness now installs its input
after the owner is ready). [2](../../test/results/adr169-direct-native-2/result.json)
and [3](../../test/results/adr169-direct-native-3/result.json) added closed
diagnostic phases. They showed that presentation and real SQL source staging
succeeded, but the regional Kubernetes reader refused the begun operation. The
channel client had passed its 30-second conversation context, while the reader
requires a deadline no later than the operation's original `NotAfter`. The client
now bounds the operation and its reads by that `NotAfter`, and the unit test
asserts it.

## Remaining

The regional Pod in that fixture still reads hub SQL (`owner-read`) to verify
the owner it observes for. The production regional entrypoint, hub listener
composition, and the installer step that enrolls generation 1 and writes the
Secret also remain. In the fixture these are synthetic harness steps.
