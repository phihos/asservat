# Product implementation status

Baseline reviewed on 2026-10-12; runtime-profile, owner-startup and regional-collection updates on 2026-10-14; installed-workflow qualification updated on 2026-10-24. This tracks the accepted first-release scope in
[product](product.md) and the [implementation slices](architecture/implementation-slices.md).
Actual commands, source snapshots, failures and subsequent corrections remain in
[implementation progress](implementation-progress.md).

**The installed investigation journey passed end to end for the first time in native92
(2026-10-24):** install with an interrupted and resumed installer, regional enrollment,
Keycloak MCP capture, regional collection/verification/publication, approved pod-status
inspection, native download, Stop, Deny revocation, expiry refusal and verified deletion
([record](../test/results/resumed-c62e02ac-native92/README.md)). S-02 is not yet complete:
its remaining exit items are tracked below. Significant identity, permissions, encrypted
storage, audit, context capture and download components exist; the broader debugging
platform is not delivered.

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
| Bootstrap with Helm | Packaged native reference tests cover replay, managed setup cleanup, uninstall preservation and the protected runtime handover. The continuation now deploys the hub API/console/MCP, worker, federation, regional connector, key service and publisher with protected inputs. | Complete and qualify the supported installed developer workflow and operational lifecycle. The chart still rejects direct runtime enablement. |
| Sign in through browser/MCP | Keycloak, session/refresh/logout and browser/MCP components have real integration evidence. The installed fixture signs in through the console, initializes processing and makes authenticated MCP preview/request calls. | Broader installed session lifecycle, reviewer step-up and the internal-user alternative. |
| Request and browse workload context | The bounded pod-status diagnostic, shared UI/MCP controls, SQL admission and encrypted publication have component/native evidence. Earlier regional fixtures complete collection, publication, case lookup, native download, Stop and revocation with synthetic authority inputs. Installed native92 completes MCP capture, publication, approved inspection and native download. | Installed browser inspection, a second workload cluster and the remaining S-02 exit checks listed below. The diagnostic remains limited to 4,096 native bytes and is not generic file/log/command collection. |
| Download, Stop and deliberately retry | The combined real-service run passes content, range resume, interrupted original/new sessions, control negatives, exactly-one-winner admission, native exchange and retention-observation expiry. Authenticated ranges reconstruct a 352-byte artifact without budget refill. Browser restart and cancellation/denial boundaries pass. Installed hub-local worker/profile provisioning and configuration acceptance also pass. | Installed transfer, Stop, revocation and expiry pass in native92. Installed Range resume, active-stream interruption on Stop, sustained availability and large-artifact qualification remain pending. The component fixture's synthetic authority inputs and earlier failures remain explicit in the chronological tracker. |
| Download every evidence type for local tools | Persistent framed format and bounded decoder exist; a separate earlier feasibility lab transferred 2 GiB. | Generic large-object publication, full native transfer/window lifecycle, interruption, throughput/memory and local-tool qualification for product cores, PCAPs and derivatives. |
| Automatic suspicious-event collection | Policy source, automation identity and acceptance components exist. | Resolved policy/trigger engine, logs/resources/probes/external triggers, all-replica observation, correlation, storm controls and fair incident dispatch. |
| Files, logs, processes and commands | Designed; pod-status is the implemented narrow exception. | Confined whole-pod adapters, bounded execution, partial/error handling, native output and platform qualification. |
| Packet/syscall rings, save and live watch | Designed; packet/compiler/peer/ring feasibility is separate from a product recorder. | Production recorders, dynamic peers, lifecycle/quotas/loss accounting, approved projections, save-only dispatch and UI/MCP live delivery. |
| Runtime profiles and offline analysis | Bounded Go pprof/trace HTTP acquisition preserves native bytes in encrypted frames. Acquisition and passive named-endpoint planning pass component tests, including a real Go CPU handler and synthetic Kubernetes API observations. Guard/node connections and catalog acceptance remain explicit fixture inputs. | Protected endpoint catalog acceptance, profile admission, qualified node dialing, custody/publication and native download; hostile-input-safe analysis, encrypted scratch/Jobs, bounded queries and derivatives. A required console flamegraph viewer has not been accepted or implemented. |
| Core dumps and compatible debugger workflows | Disposable-VM helper/crash/local-debugger feasibility exists. | Product helper lifecycle, prepaid crash path, live/process selection, exact companions, large downloads and supported node/runtime qualification. |
| Combined approval and evidence sharing | Designed; ordinary eligibility/authority foundations exist. | Independent reviewer flow, bounded collection/result grants, multiple owner-team management, future/concrete shares, recipient access and revocation. |
| Capture profiles, guidance, history and repeat | Designed; the single context preset has narrow implemented preview/recovery flows. | Versioned profile composition, useful recommendations, selector history, repeat with fresh checks and complete investigation navigation. |
| Permission/privacy administration | Protected-source, retention, restriction and deletion backend subsets have native tests. Installed console processing initialization passes. Deletion supervision is implemented and merged in PR #41, with SQL paging and focused backend-permission checks. | Processing release, browser-session cleanup, administration UX, previews/overdue reporting and complete managed-copy/backup/history lifetime closure. Installed expiry, failed-cleanup recovery and deletion charge release remain unqualified. |
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

Native92 covers the MCP path in one regional workload cluster, approved inspection,
native download with checksum, Stop, Deny revocation, expiry refusal, a failed cleanup
that retains its charges and verified deletion. Still missing from the installed run,
against the [S-02 exit](architecture/implementation-slices.md#s-02-exit-in-detail):

- a second workload cluster through the same hub;
- an unrelated principal that cannot enumerate or collect;
- browser preview/request/inspection/download and browser/MCP reply parity (the console
  implements these views; they are qualified only against synthetic case authority);
- installed duplicate and conflicting-idempotency submissions and a Range resume;
- hub disconnect/reconnect importing a committed result without repeating collection;
- user-visible Partial/Unavailable for lost target and object/KMS failure.

Future forecasts must use bounded deliverables with explicit implementation,
integration and qualification work; account for dependencies and shared foundations;
and compare estimates with measured delivery of similar completed workflows.
Report scope changes and uncertainty explicitly. Until that baseline supports a
forecast, report completed outcomes, current failures and the next acceptance test.
