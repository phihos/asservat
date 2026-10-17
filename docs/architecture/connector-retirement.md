# Prepaid retirement of a connector cohort

This integrated SQL51 continuation extends ADR-126 with an independently reserved
restrictive operation for each accepted logical connector profile. It enables
no listener or public route. The fast SQL/S3 cases pass; actual lifetime cleanup
and installed composition remain pending. See [implementation progress](../implementation-progress.md).

Additive migration 56 corrects only a nested credential-table alias in the
cleanup profile trigger. The original audit composite variable otherwise captures
`a.process_id`, causing SQLSTATE 42703 before the intended live-reference denial.
SQL51, stored identities, ACLs, original dates and accounting remain unchanged.
The focused regression reaches that trigger using a temporary fixture-only
definer under the original cleanup login; it never backdates a live process.
This negative-path test does not qualify the later full-lifetime detach.

A first process acceptance reserves one immutable ticket; backing acceptance
reserves the complete bounded successor set before any promotion. The encrypted
accepting intent includes the canonical version, count and set digest. SQL
recomputes that set from exact original canonical bytes before acknowledgement
and promotion. A late-observed peer retains its accepted behavioral identity;
its future complete source observation is never invented to build a successor.

Ordinary process/signing admissions count outstanding ticket reservations as
well as charged pairs. Retirement converts its own reservation into a pair
under the same root, profile, pool and stable peer account locks. Changing the
peer or process identity cannot refill this capacity. The new private
`connector-operation-history/v2` explicitly backs ticket/control rows and forty
fixed transitions; v1 bytes and qualification remain separate. Source-row
backing additionally covers one root, the bounded profiles and up to
`ProfileLimit * (SourceTransitionLimit + 1)` original ticket rows. Its independent WAL floor includes two transitions per
source allowance plus ten full transaction bounds per ticket slot; unused-pair
closure cannot discard the backing needed for later tombstone deletion. Type-valid
arithmetic does not constitute measured SQL/WAL/provider qualification. The
4096-profile structural ceiling does not claim complete-set admission within
five seconds; that throughput and maximum transaction footprint need separate
measurement against the accepted backend. The current native fixture source
exercises one profile/successor and two process generations.

The historical branch requires current recovery and the purpose-bound journal
role after the original ordinary admission end. It uses the immutable original
actor only as provenance, with no synthesized live principal or Pod proof. An
explicit retiring source uses the separate live retirement-only attester and
must retain the exact logical peer/source UID, accepted cohort and original
backing while observing a higher protected suspended/retiring generation.
Neither branch can retire a successor cohort with an old ticket.

Restriction commits first. Audit failure cannot undo that fence and is returned
as incomplete retirement. A distinct business transaction freezes the exact
restrictive outcome before encrypted outcome creation; the audit writer cannot
invent that result. Unknown replies reuse the original ticket/operation and
original times. An expired audit interval can still leave a useful protective
fence, but cannot be reported as acknowledged audit or successful cleanup.

At the minimum accepted retention of 2100 seconds with zero backup horizon and
60-second cleanup/proof windows, an acceptance at A fixes original object purge
at A+1860, ticket consume end at A+1830, ordinary admission no later than A+1800,
and final retained end at A+2100. The producer rejects incompatible promises
before accepting the profile. A process admitted near the ordinary end retains
its own later process, certificate and audit dates. Early backing renewal may
reserve a successor while all older possible effects and history stay charged.

Closing ticket admission irreversibly severs its accepting-pair reference only
when further original admission is impossible. Closing an ended writer's
business reference is not positive writer quiescence. Admitted pairs still use
the existing independently verified exact-object purge, deletion certificate,
finite verification allowance and history cooling. The original ticket row
can be deleted only after its original history-release instant, closed references
and corresponding positive audit/history absence. Its separately reserved row
and transaction backing remains through the unchanged retained end. This leaves
the original cleanup budget to delete the row before its hard metadata deadline;
elapsed time alone never establishes closure. A minimal, separately backed profile fence remains while
later process/leaf obligations exist. No expiry or missing Pod releases unknown
spend, and a delayed old request cannot consume a successor ticket.

The fast real-service fixture source covers reservation, original-cohort
supersession/unused close, expired ordinary admission, dead-actor historical
retirement and private role denial. The opt-in real-time source configures a
thirty-second ordinary admission interval before acceptance and admits a second
process near that real end. It preserves the actual thirty-minute
process/certificate period and 2100-second retention, waits through real
SQL/object/history/ticket cleanup and requires at least 1860 measured seconds
inside its subtest. This is a supported short-admission configuration, not a
substitute for the separate maximum A+1800 admission-boundary release gate,
which needs approximately 65 minutes. Neither real-time case has run for this
integrated candidate. Protected source/Pod/backup qualification and issuer facts remain
explicitly synthetic in these SQL/S3 fixtures.

Finite profile/source/root teardown, production qualification/provisioning and
installed connector supervision remain open. Removing the last cluster must
leave the ordinary installation root usable. Permanent root minimization is a
separately authorized full-installation action, retains one inert installation
high-watermark and cannot reset capacity under a new root ID. This ticket
component does not claim that final installation lifecycle.
