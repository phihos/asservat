# ADR-207 — One native proof bracket for context-start setup

Date: 2026-10-18. Status: registration source handoff implemented with component
tests; setup operation and native qualification remain pending.
Requirements: REQ-EXE-002, REQ-FED-001/003, S-02; TASK-03 / TASK-11.

## Context

The installed native43 journey stops at preview target resolution. The regional
process reports failed context-start openings; the independently active capacity
lane cannot answer these queries. No collection, download or deletion is reached.

The concrete executor's full proof already observes the connector, so performing
an outer connector observation immediately before that proof is redundant. The
combined reader fixes that duplication without changing the proof. It does not
fix the complete setup graph: setup still performs three local process reads,
two full hub-owner authentications and a separate source read for the first
source frame.

Each ordinary local recheck observes the source twice itself and twice through
the nested read-only SQL registration conversation. The cold executor already
has its own opening/closing source bracket under ADR-199, but that nested
conversation still makes two further full source reads. Static accounting alone
shows that removing only those cold nested reads cannot make the remaining
complete opening fit the original five seconds at 20 QPS/burst 20. This is a
source-derived cost argument, not a measured successful setup.

## Decision

1. Extend ADR-199's existing explicit `ObserveConnectorProcessAt` composition
   into its read-only registration conversation. A private per-conversation
   reader supplies the exact independently opened source, with copied buffers,
   its original start and earliest source/caller end, for exactly the registry's
   two source callbacks. The known issued leaf, process and installation remain
   exact. Configuration, enrollment and signing requests are refused. The reader
   is closed when that single conversation ends; it is never installed as an
   ambient source. SQL49, its current recovery/registration checks and roles are
   unchanged. The enclosing native proof still performs its full closing source
   read and local credential confirmation before returning a usable proof.
2. The concrete executor will own a private setup operation containing one
   complete native proof and the exact process-owned credentials instance. Its
   original proof generation must be captured atomically with the proof result.
   No subsequent generation read can make an older proof current. It can supply
   that same proof for the local checks inside this one opening, within the
   earliest original discovery/setup/proof/caller deadline.
3. The first source frame may carry the actual closing source from that initial
   complete proof, with its original dates. This explicitly refines ADR-178's
   otherwise independent full source read for that frame. Only this private
   setup operation may supply it; later work/query source reads are unchanged.
4. After HTTP response completion, an explicit closing native read must verify
   the same live namespace/account, execution SSR, exact guard policy/binding
   pairs, settings, workload and approved inputs, plus a full current source
   proof. Local confirmation must retain the same active process and installed
   leaf under that source. The opening registration's original end remains
   binding, as with ADR-199's local close. A current failure, known generation
   change, expired original interval, closed/renewed credentials or cancellation
   denies; there is no fallback to the opening result.
5. Both existing actual remote-owner authentications remain mandatory and
   current. The setup operation stays owned until after the final owner read;
   a final local generation/credential/deadline check follows that blocking
   read. Closing cancels and joins all owned work. No completed setup operation
   is retained by `exchange.Check`, a target query or accepted collection work.
   Those paths still perform their existing full current checks.

Other executor implementations retain their independent original behavior.
No QPS, admission requirement, SQL check, freshness interval, public wire field,
standby capacity or collection permission is enlarged. Setup is not collection
authority. As ADR-173/199 already specify, unobserved changes can remain unknown
within one original observation interval; no instantaneous revocation is claimed.

## Qualification

The combined-reader regression has failing-before limiter evidence and passing
component races, including exact credential ownership, copy isolation, original
cutoffs, cancellation and expiry. The setup operation, whole-opening timing/
failure tests and an installed rerun remain pending.
The registration dispatch regression fails on unchanged dispatch. Its corrected
selection passes nine top-level / 19 named race tests, including real
TLS1.3/HTTP2/exporter-bound presentation with synthetic registry/source authority.
It refuses missing/extra source callbacks, configuration or lifecycle work,
unknown leaves, foreign sources, revocation, cancellation, expiry and reuse after
close. Source copies and original cutoffs are checked. Package vets and Go
architecture pass; spec check passes 11,368 assertions and design architecture
passes 1,306 positive / 120 negative checks. No real SQL49 or native source
producer ran in that component fixture. Component fixtures and static call
counts cannot establish an installed pass.
