# ADR-278 — Encrypted-disk ring medium (S-04 increment 16)

Date: 2026-11-02. Status: accepted (agent decision, plan S8).
Requirements: REQ-NET-003 (`ring.medium`), REQ-SYS-002, ADR-036 (no plaintext
evidence at rest), docs/reviews/s04-plan-2026-10-27.md S8 and increment 16.

## Context

Ongoing packet and syscall sources keep their history in a node-local ring.
Rings live in memory only, so their size counts fully against the node's
recording memory budget. The spec offers `ring.medium: encryptedDisk` as an
optional, separately qualified administrator storage profile; memory stays the
baseline and default.

## Decision

1. Opt-in per installation: the collector gets a size-limited node-local
   `emptyDir` only when the administrator enables `collector.ringDisk`. Without
   it, a plan asking for `encryptedDisk` is refused on the node with
   `MediumUnavailable` before anything is reserved.
2. In disk mode a ring keeps all 32-byte segment headers and only the segment
   being written in memory. When writing moves on, the finished segment is
   sealed with AES-256-GCM under a key generated in memory for that ring (one
   source epoch) and written to a `0600` file; the nonce is random per seal and
   the segment index and header are authenticated data. Reads decrypt into a
   bounded scratch buffer.
3. The key is never written anywhere. Closing the ring, a restart or a crash
   loses it, so earlier segments cannot be read again (crypto-erase); closing
   also removes the files. Nothing is written unencrypted.
4. A seal that fails (for example a full volume) closes the ring with
   `MediumUnavailable`; no partial segment is treated as retained history.
5. The node's memory reservation for a disk ring is one segment plus headers;
   on-disk bytes are bounded by `ring.maxBytes` and the `emptyDir` size limit.
   No CSI/StorageClass, no `storageProfileRef` in this release.

## Complexity gate

Benefit: rings beyond node memory for long ongoing history (uncommon; spec
option). Cost: one opt-in Helm value and volume, one storage mode in the ring,
one wire field; no new service, state or credentials. Disabling it is the
default.

## Qualification

Unit (real files): the complete ring suite runs on both media; closing removes
the files and the key; a tampered sealed segment is evicted as a coverage gap;
an unwritable volume closes the ring with `MediumUnavailable`; the node refuses
an encrypted-disk source without a mounted volume and reserves one segment plus
headers with one. `check-helm.py` renders the opt-in emptyDir as the only
writable collector mount. A native installed run with the volume enabled
(restart, byte cap, full volume on a real node) is still pending.
