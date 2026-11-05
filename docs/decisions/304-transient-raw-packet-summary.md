# ADR-304: Fixed transient summaries of raw packet recordings

Date: 2026-11-05. Status: implemented and reference installed workflow qualified;
broader qualification remains scoped below.
Requirements: REQ-NET-005, REQ-EVD-005/008, REQ-MCP-003/005, REQ-DLD-001.
Extends [ADR-303](303-saved-packet-summary.md) using the accepted bounded Go
mechanism in [ADR-286](286-bounded-go-analyzer-isolation.md).

## Decision and authority

The maintainer delegated the bounded-analysis mechanism in ADR-286. Apply it to
one fixed metadata projection of an already published raw packet recording,
following the existing raw-pprof summary pattern in ADR-291. This is an
implementation choice within that accepted mechanism, not a new request for
raw access or a reduction of the remaining analysis scope. The S-05 plan's S4
already describes these query results as transient.

`get_pcap_summary` may return the qualified, independently checked numeric
summary of that original. The source remains raw, with its original type,
audience, privacy classification, retention and native-download grant. A query
creates no stored derivative. The native-download requirement for retained
artifacts and saved derivatives does not require saving each transient DTO.
Native tools retain ADR-036's separate Jobs and qualified encrypted scratch.
Arbitrary raw fields remain a separately granted `pcap_query` operation.

This explicitly supersedes older packet/MCP prose that required every raw
packet summary to create a stored extract through the sandbox. It does not
classify arbitrary analyzer output as an extract or enable other raw readers.
The metadata-only source in ADR-303 keeps its existing format and display version.

## Exact source, authority and output

The new source is exactly `RawPCAPNGArtifact`, `pcapng-raw`, raw class and
`packetCapture`/`rawPackets`, with display definition
`approved-raw-pcap-summary/v1`. Authenticated source/version and authored default
and transport-specific prefix limits remain binding. A new `ReadPacketSummary`
operation requires current ordinary target rights, retained audience, complete
denies, extract/packetCapture client policy, processing, retention and recovery.
Generic `ReadApproved` and raw download/query authorization keep their scopes.
The raw aggregate has no share fallback.

An optional packet-route facet returns the closed metadata/raw discriminator
from the existing bounded route lookup. It adds no lookup. The protected catalog
must subsequently match that discriminator and the complete expected source;
the route is not authority. A reader without the facet retains metadata-only
behavior. Raw scope, worker, key, result and audited public-delivery checks all
bind the dedicated raw display definition and exact original source.

The result uses `capture_mode: rawPackets`. `packets` counts every saved packet
record, including a prefix too short to classify. Raw results require
`unclassified_packets`, including zero. They never invent endpoints for missing
headers. Conversations contain only classified numeric endpoint/protocol groups;
their full count, deterministic top100 and truncation retain ADR-303's meaning.
The count represented by those groups is `packets - unclassified_packets`.
Metadata results omit the new field and preserve their existing JSON.

Producer exclusions and unavailable statistics retain their existing explicit
labels and never become measured network loss. Unclassified records are saved
records, not additional drops. Payload, names, comments and arbitrary strings
are outside this projection. Complete authenticated native EOF and closure
precede output; late corruption or lost authority overrides computed results.

Native input remains at most8MiB, blocks256KiB, aggregates16,384 and full output
24KiB. One existing worker, two read units and three one-use key roles fund the
query. Original deadlines, conservative unknown spend, audit acknowledgement
and joined cleanup remain unchanged. These limits require qualification of raw
payload, maximum aggregate and tiny-prefix shapes with crypto and transport;
they are not measured resource usage or proof of successful completion.

## Complexity and qualification

| Question | Cumulative answer |
| --- | --- |
| 1. Observed need | All existing raw packet sources are refused by the metadata-only summary. This is a required investigation path; no observed exploit is claimed. |
| 2. Accepted risk | Reuse ADR-286's accepted shared worker and preserve separate raw-query/download grants. |
| 3. Typical use | Inspect saved network metadata without requesting raw bytes or another capture. |
| 4. Precedent | Existing raw-pprof aggregate authority and metadata-PCAPNG query/worker path; no new coordination mechanism. |
| 5. Added privileges | Zero roles, credentials or destinations; parser code shares existing scoped worker credentials. |
| 6. Added states | Zero persistent lifecycle states. Unclassified count is an output fact. |
| 7. Added configuration | Zero operator knobs or new resource profiles. |
| 8. Dependencies | Zero new dependencies, CSI drivers or external tools. |
| 9. Aggregate cost | One existing worker/query, max8MiB input, two read units, three key roles and100 rows/24KiB output. Zero additional watches or background loops. Combined raw cost must be measured. |
| 10. Upgrade/rollback | Additive closed function migration; retained raw queries prevent downgrade. Minimized audit cannot distinguish source class, so any retained packet-summary audit conservatively prevents downgrade. No stored query is rewritten. |
| 11. Smaller solution | Reuse transient projection. A stored derivative and three-Job/PVC pipeline add no required outcome for this query. |

Qualification must cover exact ordinary/raw boundaries, client and retained
rights, malformed/maximum/tiny-prefix inputs, actual receiver and complete
encrypted key/store read, compiled SQL roles and rollback, built React, then the
installed MCP/browser summary and same-original native PCAPNG parity. Include a
synthetic payload marker that never appears in approved output or normal logs.
No checkbox or component pass establishes an installed raw-summary workflow.

## Qualification

PR167 merged as `897fd783` with the complete tree equal to reviewed `b6e2c084`.
Eligible pull-request CI41960208068 passed all15 jobs. The
[installed manual-raw reference](../../test/results/raw-packet-summary-native-41960249012/README.md)
passed Go/harness0 in773.697s: ordinary read-only MCP and actual React summaries
matched the same authenticated9,400-byte original through native/tshark parity,
54 saved records, two directional groups and0 unclassified records. Payload
remained in the raw original and was excluded from the fixed output. Both paid
queries passed source/account/three-key/worker terminal checks. All4,212 reported
source hashes matched Git, sources stayed unchanged, cleanup was empty and
scratch removed. Conditional retirement proof and unused later callback limits
remain explicit in the report.

Local compiled-role lifecycle/upgrade, built React and five named resource
containers have separate retained evidence in implementation-progress.md.
Those resource inputs do not establish every installed maximum or sustained
500m throughput. Second-workload/replay/Repeat checks and arbitrary raw
`pcap_query` were not exercised by this focused native run; complete S-05 is
unfinished.
