# ADR-303: Saved packet metadata summaries

Date: 2026-11-05. Status: implementation; integrated and installed qualification pending.
Requirements: REQ-NET-005, REQ-EVD-005/008, REQ-MCP-003/005, REQ-DLD-001.

`get_pcap_summary` reads one already published metadata PCAPNG through the existing
regional approved-query worker. Reuse ADR-286's bounded Go class, ordinary current
and retained rights, immutable source/version, retention/recovery, prepaid ledger,
three one-use key roles, audit, finite result delivery and joined cleanup. No
acquisition, new Job kind, service, role, Secret, network lookup or scratch volume
is added. This does not authorize raw packet inspection or advertise a sandbox.
Raw packet queries and reviewed extracts remain separate unfinished requirements.

Bounds: native input at most8MiB; block at most256KiB as in the canonical checker;
at most16,384 directional endpoint/protocol aggregates; deterministic top100;
result at most24KiB. Endpoints are numeric; no DNS, names, comments or payload
are exported. Full authenticated EOF and source closure precede any result.
Malformed tails, excess parser work, invalid counters and source/provider errors
refuse the result, retaining conservative spend. The fixed result shape has no
independent size-selector or successful TooLarge variant. These are engineering
bounds, not measured overhead or proof of every maximum-input shape.

Two read-work units fund the existing full8MiB/index/manifest read, matching the
HTTP/syscall paths. The existing256MiB physical/transient minimum remains; actual
worker limits and composed parser/crypto/transport cost require qualification.
A configured limit is not a hard Go per-query heap or successful-run guarantee.

The output counts saved packet records and reports directional traffic groups,
not distinct TCP connections or unique datagrams. `conversations_total` and
`conversations_truncated` explicitly distinguish the full aggregate set from
its top100 table. Public query observation/expiry and nested poll tool/provenance
association match the other approved views. The console starts only on explicit
inspection and clears its managed view on source/session/scope loss or expiry.

PCAPNG statistics are optional cumulative interface counters; interface resource
drops, OS drops and filter acceptance have distinct meanings in the
[IETF working draft section4.6](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-06.html#section-4.6).
Existing finite Asservat PCAPNG writes excluded/not-retained plus lost events;
saved-window PCAPNG writes output-limit exclusions. Preserve those authenticated
artifacts and label their actual meaning with `drop_reporting` (`captureExclusions`
or `snapshotOutputLimit`). Missing counters mean null/`unavailable`, never zero
loss. Track known cumulative lower bounds separately from latest field presence;
reject a later decrease even across an omitted counter. This does not retroactively
claim physical-interface loss or complete traffic coverage.

Complexity: the required investigation route is missing; exploit frequency is
unmeasured. It serves ordinary metadata investigations and follows existing
approved projections. Add zero privileges/dependencies/API watches/operator knobs
or fallback states. Each query has one bounded read and existing key/audit work,
with no background mechanism. An additive function-only SQL migration extends the
closed source/tool/scope/resource checks; downgrade refuses retained new queries
or audit. This is smaller than a separate query service or generic expression API.

Qualification must include hostile/maximum shapes, authenticated complete read,
current authority and compiled process roles, upgrade/rollback, browser/MCP parity,
real React-driver checks, and the installed saved-summary/native PCAPNG workflow.
Contract/component success alone establishes none of those installed outcomes.

Use `make packet-summary-preflight` for affected local component checks. The
compiled-role packet lifecycle and schema upgrade use separate frozen owned
service fixtures. `make console-browser-check` includes the real compiled React
packet driver against synthetic local service facts; it is not an installed
permission/storage/collector claim. Final native qualification extends the
existing manual-mixed suite, preserving its original job, query and time limits.
