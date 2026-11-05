# Saved packet queries: local evidence

The implemented query reads an existing authenticated metadata or raw PCAPNG,
applies the pinned tcpdump/libpcap subset and typed time/flag selectors, and
returns bounded primitive fields in React and MCP. Raw sources require their
own current `pcap_query` grant, including header-only selections. No query
implicitly collects evidence. Source and output bounds are distinct.

Named local checks passed:

- Full `make go-check`: 68 full packages and 691 Kubernetes tests in 18
  sequential groups, with one intended explicit native skip. This run began
  at `10e324ab`; ordinary compilation overlapped later formatting-only test
  and SQL changes. It is not an exact final-tree whole-suite claim.
- Integrated pre-push on `b2759438`, including 529 console tests and the
  generation, formatting, vet, SQL and contract gates.
- Full built-console browser gate on `bb936966`: Go exit 0 in 107.539 seconds,
  retaining 28 journeys and 27 accessibility scans. Metadata ordinary access,
  actual raw approval controls, null/zero/short-prefix cells and nested limited
  results pass. Browser authority is synthetic. The source snapshot remained
  unchanged; later SQL/test-only changes have separate service evidence.
- Packet-focused race/preflight checks, the actual pinned libpcap compiler and
  static hub build, contract/output races, and the affected approval/retry UI
  tests. Per-owner handoffs retain exact files and command outcomes.

Earlier failures remain original evidence. They include an undersized nested
response margin, missing actionable raw-review refusal, an uncertain Begin
allowing a replacement request, nested limit flags being ignored, and missing
required limited-result hints. The first full browser run failed before the
hint correction; the fresh corrected gate above passed. Policy-schema bundle
drift, a vet literal and test formatting were also corrected after failed gates.
No failed campaign is relabeled as a pass.

The final evidence-assembly pre-push exited 2 solely because the service archive
README had not yet been written when the link checker ran. All other gates,
including 529 console tests, passed. After all three documentation files and
archives were frozen, the affected spec, architecture and design gates exited
0. A final native/upgrade-helper race run also exited 0 in 6.540 seconds. Both
the failed assembly log and the corrected documentation checks are retained.

The real PostgreSQL/S3 lifecycle and upgrade campaigns, including the account
guard, key-binding-size and fixture-cleanup corrections, have separate
[service evidence](../saved-packet-query-services-local/README.md). Fresh bounded
consumer campaigns have separate
[resource evidence](../saved-packet-query-resource-local/README.md). Configured
500m CPU is not qualified sustained throughput.

`manifest.json` records original paths, sizes and SHA-256 hashes alongside the
deterministic gzip members. Every member was decompressed and compared with
its original bytes. Browser screenshot archives remain in the local cache;
their source/readback metadata is retained here. Earlier handoffs keep their
own snapshots rather than retroactively qualifying a later whole tree.

Installed packet-query qualification, pull-request CI and merge remain pending
at this checkpoint. These local results do not complete S-05 or qualify a release.
