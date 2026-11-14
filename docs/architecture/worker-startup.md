# Regional reader

Downloads and stored-evidence queries are served by a long-running regional
reader Deployment (A-ACQUIRE; a hub Deployment in combined mode)
([ADR-330](../decisions/330-event-driven-system-design.md) D4). It is scaled
by replicas. There is no Kubernetes Job, certificate or key slot per download
or query.

## Identity and connection

- The reader authenticates to the connector, or in combined mode to the hub,
  with an audience-bound projected ServiceAccount token. The receiver checks
  it once per connection with TokenReview ([peer identity](peer-identity.md)).
  Server TLS uses the installation CA.
- Each replica holds one long-lived HTTP/2 stream on which the hub pushes
  work (download, approved pod-status read, query). The reader reconnects only
  after a failure, with exponential backoff. It does not poll for commands.
- Download bytes travel as a stream on the connector connection
  ([connector connection](regional-context-start.md)) to the hub, which
  relays them to the authenticated caller (I-13).

## Work

A work item names the download session (or query), the artifact, the byte
range and the operation deadline. The hub creates it only after it has
authorized the operation ([download authority](download-authority.md)). The
reader:

1. reads the encrypted object from the regional object store with its
   read-only store credentials,
2. asks the key service (I-14) to unwrap the artifact's data key for that
   session; the key service checks the session row in SQL once,
3. decrypts and streams the plaintext bytes,
4. stops at the session's original bounds: caller session/token expiry,
   session deadline, `AccessUntil`, the stored retention cutoff, Stop or
   cancellation ([ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md)).

Stop and retention cut-offs reach the reader as stream resets pushed by the
hub (PostgreSQL `LISTEN/NOTIFY` on the session row), not by periodic
rechecks. The hub never unwraps evidence keys; plaintext exists only in the
reader and in the caller's response.

Every work item carries the session's idempotency key. A repeated item for a
session that already has a stream resumes or rejects it according to the
session state in SQL; an unknown outcome is resolved by that lookup.

## Configuration

Helm values rendered into a mounted ConfigMap: hub/connector endpoint,
object-store endpoint, bucket and region, key-service endpoint and the CA
bundles. Store credentials come from a mounted Secret. The reader reloads both
on file change and logs the accepted revision and digest. No SQL credential,
wrapping root or user session enters the reader.

## Process hardening

The reader runs non-root under Pod Security `restricted`, with a read-only
root filesystem and all capabilities dropped. On Linux it disables its own
core dumps before handling key material and refuses to start if that fails.

## Ownership

C-20 owns the wire shapes, C-21 the store, key-service and token adapters,
C-14 the read use case and supervision. `cmd/asservat` selects the role;
`internal/bootstrap` chooses concrete adapters.
