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
   Snapshot copies walk the ring once, since every walk decrypts sealed
   segments under the ring lock.
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
5. The node's memory reservation for a disk ring is one segment plus headers.
   `collector.ringDisk.bytes` sets both the `emptyDir` size limit and the
   node's `ringDiskBytes` ceiling; the node admits a disk ring only while all
   active disk rings, sealed with nonce and tag, fit in it, so the kubelet
   limit (which would evict the collector Pod) is never reached. On start the
   node removes earlier processes' ring files, which outlive container
   restarts but are unreadable without their keys. No CSI/StorageClass, no
   `storageProfileRef` in this release.

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
writable collector mount. The installed save path on the disk ring passes
natively (`continuation-ongoing-save-disk`, PR #133).

Native node behaviour (2026-11-02, `collector-ringdisk`, runs 41528226602
and 41528974254 on GitHub runners, kernel 7.0 Azure, kind, chart volume at
its 16 MiB minimum, rings of three 4 MiB segments so exactly one fits):

- Byte cap: the first encrypted-disk source is accepted (4,194,400 bytes of
  ring memory reserved); a second one is refused with `MediumUnavailable`
  and the reservation stays unchanged. The volume peaked at 8,388,600 bytes
  (two sealed 4,194,300-byte `0600` files) against the 16 MiB limit; the
  collector Pod was never evicted.
- Sealing: the sealed files hold neither client/server address pair, which
  the decrypted snapshot of the same ring does contain (positive control).
- Restart: after SIGKILL of the collector process the container restarts in
  the same Pod with the emptyDir intact; the new process logs
  `removedEarlier=1`, the volume is empty and the old source is gone from
  the report (a snapshot of it is refused as unavailable).
- Full volume: the test mounts a 1 MiB tmpfs over the Pod's emptyDir on the
  node before a second container restart, so the first seal of a 4 MiB
  segment hits a real ENOSPC. The ring closes (`stopped: ring medium
  unavailable`, source InputUnknown), no partial file or ring directory
  remains, a snapshot is refused (`CaptureBusy`) and the reservation is
  released. The tmpfs is test-only node manipulation; the chart has no such
  option. A volume filled by other writers on a shared node disk is not
  exercised.
