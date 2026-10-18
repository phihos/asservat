# ADR-207 — One native proof bracket for context-start setup

Date: 2026-10-18. Status: registration source handoff and private setup operation
implemented with component and selected native tests; installed qualification
remains pending.
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
2. The concrete executor owns a private setup operation containing one
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
cutoffs, cancellation and expiry. The setup operation and whole-opening
component tests now exist; selected native setup passes as recorded below, while
an installed rerun remains pending.
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

The final affected setup selection passed 30 top-level / 69 named races across
mTLS and Kubernetes, followed by touched-package and integration vet and
integration compile-only (zero native tests). The preceding wider selection
passed 32 top-level / 90 named cases and the Go architecture gate. These cover
atomic proof generations, one source frame and closing operation, original
cutoffs, parent/caller cancellation, joined closure, errors throughout an actual
loopback HTTP/2 opening and later full exchange checks. Removing setup dispatch
from the exact final fixture reproduced both expected failures; the original
source was restored before the passing selections.

The synthetic limiter model accounts for 114 observer calls and 24 probe calls
(two installed inputs), at 20 QPS/burst 20, plus two synthetic current-owner
checks. Its measured loopback opening took 4.706 seconds; its best-case observer
wait alone is 4.7 seconds. This is not native latency or concurrent availability
qualification. No limiter or observation interval is enlarged.

Independent review found the existing local credential confirmation could return
after its active key changed during chain verification, or after a shorter
caller deadline before the cancellation timer ran. It now rechecks the exact
active process, installed leaf, root, caller and original source/registration
interval under its lock after verification. The closing native result also
narrows its original caller cutoff before final freshness validation, without
hiding a producer that tried to extend the original interval. Deterministic
failing-first regressions cover both boundaries. The native fixture now contains
an original cold setup, no-I/O local reads, current closing API/source checks,
and a changed-input refusal. The first selected native run passed the cold setup
case, but failed a later independent work that reused the setup's nearly expired
proof after CRD readiness; the input-change case did not reach its mutation.
That complete first fixture failed. The corrected independent-phase separation
passed all five selected native cases on frozen
`0099e2295d3fdd63cb2892170a6152872e2e56b8`: cold setup 1.804 seconds, closing
checks 0.699 seconds, and actual work admission/start 2.572 seconds within its
original five seconds. Changed-input refusal occurred before original expiry.
All 2,695 source hashes matched, source stayed unchanged and cleanup had no
failures. This one-input fixture retains synthetic connector source, issuer and
registry facts; full installed source and owner composition remain unqualified.
Both runs are retained in
[implementation progress](../implementation-progress.md).
