# Missed local investigation workflow and correction

The maintainer identified this gap on 2026-10-09: downloading packet captures for Wireshark, cores for GDB, and **all gathered evidence** for appropriate local tools is an elementary product workflow.

## Origin and review failure

The preserved [original brief](../research/original-brief.md) line 191 prohibited raw files and presigned URLs. Earlier design work propagated that into AGENTS.md and interface boundaries. The [tabletop review](use-case-walkthroughs.md) exercised authorization, target identity, failures, resource budgets and retention, but did not test completion in ordinary developer tools. Those reviews were specification consistency checks, not user validation; treating their outcomes as sufficient ergonomics review was a mistake. The original remains unchanged for provenance; the current user instruction supersedes its export restriction.

Encrypted managed storage, authenticated access and truthful retention notices are compatible with native file download. The product now specifies this under [REQ-DLD-001–004](../../specs/artifact-downloads.md). No blanket per-format exclusion remains. This correction does not remove independent raw-access review or claim that local files can be erased by the service.

## Task-completion regressions

| Task | Complete user outcome | Required negative/partial case |
| --- | --- | --- |
| Ordinary developer investigates production TCP failure | Select existing saved capture, Download PCAPNG, open in local Wireshark; no lead/admin role needed | Sanitized/truncated capture remains labeled; no hidden payload or fabricated history |
| Developer inspects a native crash | Download core and selected authorized exact executable/symbol companions, verify checksums and open in compatible GDB | Missing symbols/build mismatch are visible; core download remains possible; no current-image substitution |
| Developer uses a profiler, editor or script | Download native pprof/runtime trace, logs, file snapshot, syscall stream or command output | Structured projections retain their real format; no conversion masquerading as original data |
| Developer loses connectivity during a large transfer | Resume immutable file with fresh authorization and correct checksum, or receive a clear bounded-restart requirement | Revocation/expiry/uncertain bytes do not resurrect access or reset quota |
| Recipient receives selected evidence | Download exactly the shared approved artifacts, or request missing reviewed raw-download authority | No hidden parent/companion discovery; copied URL gives no access |
| Developer returns after managed expiry | Existing local file remains outside service control; new server downloads fail | UI never claims that the local copy was automatically erased |

Status: contracts and synthetic mockups/checks only. Real Wireshark/GDB/native-format, relay, resume, leakage, capacity and participant tests are **NOT RUN**. Future reviews must define a developer's final observable result first, include their ordinary external tools, and label unsupported outcomes as product gaps rather than successful denial paths.

## Source checks

[Wireshark's own guide](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html) documents opening saved pcap/pcapng files. [GDB's file commands](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Files.html) distinguish executable/symbol inputs and core memory. These support the native-file workflow; they do not establish compatibility of an arbitrary runtime dump. [HTTP range semantics](https://httpwg.org/specs/rfc9110.html#range.requests) support partial retrieval, but authenticated Asservat resume and its encrypted/compressed backend require implementation qualification. No legal claim follows from these sources.

Historical state before ADR-045 (superseded): the two-review issue was explicit: collection authority and raw-file disclosure authority are distinct in the accepted design. Existing covering download grants are reused and one artifact review can cover multiple selected existing files. Combining future collection and download review would require a bounded future-output authorization design; this correction does not invent that approval implicitly.

Follow-up [user-task review](user-task-review.md) reproduced a request/grant enum mismatch in this download correction and records its fix. The maintainer subsequently selected combined bounded collection/result review (ADR-045), superseding the earlier unresolved separate-review limitation.
