# Product implementation status

Baseline reviewed on 2026-10-12; runtime-profile, owner-startup and regional-collection updates on 2026-10-14; installed-workflow qualification updated on 2026-10-18. This tracks the accepted first-release scope in
[product](product.md) and the [implementation slices](architecture/implementation-slices.md).
Actual commands, source snapshots, failures and subsequent corrections remain in
[implementation progress](implementation-progress.md).

**The packaged initial bootstrap and protected observation-mode owner startup
have passed their native reference tests. The complete installed developer
investigation workflow is unfinished.** Significant identity,
permissions, encrypted storage, audit, context capture and download components exist.
Their component tests do not establish delivery of the broader debugging platform.

No overall completion percentage or ETA is established. Earlier conversational
45–50% and 35% estimates lacked a consistent scope/effort baseline and are withdrawn.
Counting documents, code, passing tests or checklist rows cannot supply that missing
measurement. The same applies to the earlier 6–12 week ETA.

## Evidence levels

- **Designed:** accepted behavior/contracts exist; prototypes and mechanism spikes
  are distinguished from product implementation.
- **Component implemented:** concrete product code has relevant unit or component
  tests; its installed dependencies may be absent.
- **Integrated:** components communicate in a fixture. Any synthetic identity,
  installation, permission or capacity inputs remain explicit.
- **Native-tested:** the named boundary passed against real APIs/providers/SQL/TLS,
  containers or the built browser. This may still use synthetic authority inputs.
- **Installed workflow:** the intended operator/developer completes the named flow
  with packaged product services and supported inputs.
- **Production-qualified:** the applicable failure, privacy, operational, scale,
  compatibility and usability exits pass for the advertised support profile.

These levels are evidence categories, not equal amounts of remaining work. A native
component test is not an installed workflow. Shared foundations count once across
the features that depend on them.

## Capability baseline

| Developer or operator outcome | Established evidence | Work still required |
| --- | --- | --- |
| Bootstrap with Helm | Packaged native reference test passes, including replay, managed setup cleanup and uninstall preservation. The separate full bootstrap-to-runtime guard handover also passes with nineteen inert resources and lost-response recovery. | Deploy the actual hub/console/MCP/collector services with qualified protected inputs. The chart still rejects runtime enablement. |
| Sign in through browser/MCP | Keycloak, session/refresh/logout and browser/MCP components have real integration evidence. | Installed identity/source/provider composition, reviewer step-up and the internal-user alternative. |
| Request and browse workload context | The bounded pod-status diagnostic, shared UI/MCP controls, SQL admission and encrypted publication have component/native evidence. The regional real-service fixture journey now completes collection, publication, case lookup, native download, Stop and revocation (native36/37). | Complete installed two-cluster request-to-case flow. Native44 still fails at preview target resolution before capture; the targeted native setup pass does not qualify the installed composition. The current diagnostic is limited to 4,096 native bytes and is not generic file/log/command collection. |
| Download, Stop and deliberately retry | The corrected combined real-service run passes ordinary content, range resume, interrupted original/new sessions, control negatives, exactly-one-winner admission, native exchange and real retention-observation expiry. Authenticated ranges reconstruct a 352-byte artifact without budget refill. Browser restart and cancellation/denial boundaries also pass. | Installed identity/provider composition, sustained availability and large-artifact qualification remain pending. The native fixture uses explicit synthetic identity/bootstrap facts; earlier failures and the correction of its write-on-read retention source remain in the chronological tracker. |
| Download every evidence type for local tools | Persistent framed format and bounded decoder exist; a separate earlier feasibility lab transferred 2 GiB. | Generic large-object publication, full native transfer/window lifecycle, interruption, throughput/memory and local-tool qualification for product cores, PCAPs and derivatives. |
| Automatic suspicious-event collection | Policy source, automation identity and acceptance components exist. | Resolved policy/trigger engine, logs/resources/probes/external triggers, all-replica observation, correlation, storm controls and fair incident dispatch. |
| Files, logs, processes and commands | Designed; pod-status is the implemented narrow exception. | Confined whole-pod adapters, bounded execution, partial/error handling, native output and platform qualification. |
| Packet/syscall rings, save and live watch | Designed; packet/compiler/peer/ring feasibility is separate from a product recorder. | Production recorders, dynamic peers, lifecycle/quotas/loss accounting, approved projections, save-only dispatch and UI/MCP live delivery. |
| Runtime profiles and offline analysis | Bounded Go pprof/trace HTTP acquisition preserves native bytes in encrypted frames. Acquisition and passive named-endpoint planning pass component tests, including a real Go CPU handler and synthetic Kubernetes API observations. Guard/node connections and catalog acceptance remain explicit fixture inputs. | Protected endpoint catalog acceptance, profile admission, qualified node dialing, custody/publication and native download; hostile-input-safe analysis, encrypted scratch/Jobs, bounded queries and derivatives. A required console flamegraph viewer has not been accepted or implemented. |
| Core dumps and compatible debugger workflows | Disposable-VM helper/crash/local-debugger feasibility exists. | Product helper lifecycle, prepaid crash path, live/process selection, exact companions, large downloads and supported node/runtime qualification. |
| Combined approval and evidence sharing | Designed; ordinary eligibility/authority foundations exist. | Independent reviewer flow, bounded collection/result grants, multiple owner-team management, future/concrete shares, recipient access and revocation. |
| Capture profiles, guidance, history and repeat | Designed; the single context preset has narrow implemented preview/recovery flows. | Versioned profile composition, useful recommendations, selector history, repeat with fresh checks and complete investigation navigation. |
| Permission/privacy administration | Substantial protected-source, retention, restriction and deletion backend subsets have native tests. | Installed supervision, administration UX, previews/overdue reporting and complete managed-copy/backup/history lifetime closure. |
| Incident notification and recurrence investigation | Designed, with narrow context case/navigation components. | Trigger-to-case grouping, notification delivery, timelines, findings and recurrence comparison. |
| Small deployment alternatives | Local wrapping/signing/key-service components exist. | Installed internal accounts, local PKI lifecycle, bundled PostgreSQL/pgBackRest/evidence store and provider lifecycle qualification. |
| Recover, upgrade and operate production | Initial bootstrap and database-incarnation fencing have native evidence. | Supported restart/restore activation, failover, partitions, upgrades, sustained operation, support matrices and complete production acceptance. |

The [detailed baseline](../test/results/implementation-baseline-20261012/INVENTORY.md.txt)
records 17 capability groups and seven shared dependencies, with
[source hashes](../test/results/implementation-baseline-20261012/sources.json).
It is a dated evidence snapshot; later tracker entries supersede its transient
failure descriptions. These rows are deliberately not converted into a percentage.

## Next product milestone and forecasting basis

S-02 remains the next complete developer outcome: use an installed hub to select
an authorized workload in either of two clusters, preview/request context through
browser and MCP, collect and publish encrypted evidence, inspect/download it, then
verify denial on expiry/revocation and deletion of managed copies. Authority and
capacity must come from product-provisioned accepted sources, not fixture seeding.

The regional fixture journey (capture → publication → case → phase-bounded
download continuation per [ADR-167](decisions/167-phase-bounded-download-continuation.md)
→ native bytes → Stop → revocation) now passes twice, with explicit synthetic
authority inputs. Outbound-only regional enrollment now runs in product
processes: the ADR-168 cluster credential, the ADR-169 delegated channel and
ADR-170's `hub-federation`/`connector` binaries pass as Pods in two clusters with
synthetic setup roots. Regional context collection now runs hub-driven under
ADR-171: the hub runs the runner with its own SQL/authority ports and the region
answers only cluster-local operations. The native public journey passes this way.
ADR-172 removes hub SQL from regional owner discovery and authentication at
component level. The connector executor's private context setup now has a
passing targeted real-Kubernetes test with one startup input and synthetic
connector source/issuer/registry facts. It does not include the complete
installed TLS opening and both delegated owner authentications.

[Installed native44](implementation-progress.md#installed-native-44-preview-still-unavailable-2026-10-18)
failed four preview requests at target resolution, before capture. The context
standby repeatedly refused opening while the separate capacity observation
channel remained active. Exact tested source hashes matched and fixture cleanup
completed. Current work is to identify the failing opening stage while preserving
original authority deadlines, then qualify the complete installed capture,
publication, native download and revocation/expiry/deletion path. Neither the
component pass nor a healthy capacity channel establishes this workflow.
Most collector, recording, analysis and sharing work follows or reuses these
foundations; it has not been declared complete.

Future forecasts must use bounded deliverables with explicit implementation,
integration and qualification work; account for dependencies and shared foundations;
and compare estimates with measured delivery of similar completed workflows.
Report scope changes and uncertainty explicitly. Until that baseline supports a
forecast, report completed outcomes, current failures and the next acceptance test.
