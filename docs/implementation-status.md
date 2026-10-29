# Product implementation status

Status checked on **2026-10-29** against merged main through
[PR #104](https://github.com/phihos/asservat/pull/104) and the separately identified
unmerged [PR #103](https://github.com/phihos/asservat/pull/103). This tracks the
accepted first-release scope in [product](product.md) and the
[implementation slices](architecture/implementation-slices.md). Actual commands,
source snapshots, failures and corrections remain in
[implementation progress](implementation-progress.md).

**There is no supported homelab release yet.** The control plane and several
installed developer workflows exist. The complete recording, inspection and
operational platform is unfinished. Merged code, focused installed tests and
production qualification are distinguished below.

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
| Sign in through browser/MCP | Keycloak session/refresh/logout and browser/MCP components have real integration evidence. Installed tests sign in through the console, initialize processing, make authenticated MCP calls and perform configured reviewer step-up for an approved recording. | Broader installed session/identity-provider lifecycle, operator configuration and the internal-user alternative. |
| Request and browse workload context | The bounded pod-status diagnostic, shared UI/MCP controls, SQL admission and encrypted publication have component/native evidence. Earlier regional fixtures complete collection, publication, case lookup, native download, Stop and revocation with synthetic authority inputs. Installed native107 completes browser and MCP capture, publication, approved inspection and native download in two workload clusters. | Reconnect import and Partial states listed below. The diagnostic remains limited to 4,096 native bytes and is not generic file/log/command collection. |
| Download, Stop and deliberately retry | Real-service component tests cover ranges, interrupted original/new sessions, control negatives, exactly-one-winner admission and retention-observation expiry; authenticated ranges reconstruct a 352-byte artifact without budget refill. Installed native107 covers context transfer, Range resume, Stop, revocation and expiry. | Active-stream interruption on Stop, sustained availability and larger cores/profiles remain pending. PR #103 now passes its named near-8-MiB paced packet stream, ranges and renewal workflow; this remains unmerged and scoped to the reference profile. |
| Download every evidence type for local tools | Native context download and bounded manual packet PCAPNG download have installed evidence; the current packet cap is 8 MiB. Persistent framed formats and decoders exist. The earlier 2 GiB feasibility lab remains separate prototype evidence. | Large cores/profiles/derivatives and their full publication/window/memory/local-tool qualification remain. PR #103 now passes its named near-full PCAPNG paced stream, ranges, renewal and final completion. Larger cores/profiles and other supported profiles remain unqualified. |
| Automatic suspicious-event collection | Restart, probe, Alertmanager, log and resource trigger implementations are merged. Focused installed log/resource and bounded recurring-sharing journeys passed ([PR #82](https://github.com/phihos/asservat/pull/82), [PR #79](https://github.com/phihos/asservat/pull/79)). Only bounded counts/metadata leave detector readers. | Ongoing source arming, complete storm/scale coverage and unsupported cgroup-only metrics/log-stream selectors remain. The finite policy-packet grant path in PR #103 passed its named installed workflow; broader backing, maximum-shape and ongoing paths remain unfinished. |
| Files, logs, processes and commands | Designed; pod-status is the implemented narrow exception. | Confined whole-pod adapters, bounded execution, partial/error handling, native output and platform qualification. |
| Packet/syscall rings, save and live watch | Bounded manual header-only PCAPNG capture through the published Inspektor Gadget is merged and native-tested on the named disposable Linux/amd64 profile ([PR #95](https://github.com/phihos/asservat/pull/95)). Approved request continuation passed an installed workflow ([PR #100](https://github.com/phihos/asservat/pull/100)). Each capture is finite, has no prehistory and is capped at 8 MiB. | Ongoing packet/syscall sources, rings, dynamic peers, Save existing recordings and live delivery remain unfinished. The collector retains its disposable-test-host guard. PR #103 passes its named finite policy/privacy and renewed-stream qualifications; browser recording history/repeat remains unqualified. |
| Runtime profiles and offline analysis | Bounded Go pprof/trace HTTP acquisition preserves native bytes in encrypted frames. Acquisition and passive named-endpoint planning pass component tests, including a real Go CPU handler and synthetic Kubernetes API observations. Guard/node connections and catalog acceptance remain explicit fixture inputs. | Protected endpoint catalog acceptance, profile admission, qualified node dialing, custody/publication and native download; hostile-input-safe analysis, encrypted scratch/Jobs, bounded queries and derivatives. A required console flamegraph viewer has not been accepted or implemented. |
| Core dumps and compatible debugger workflows | Disposable-VM helper/crash/local-debugger feasibility exists. | Product helper lifecycle, prepaid crash path, live/process selection, exact companions, large downloads and supported node/runtime qualification. |
| Combined approval and evidence sharing | Independent ad hoc acquisition approval, configured Keycloak step-up and continuation of the original approved recording are merged. Sharing, recipient views, multiple manager teams, capture-time sharing and bounded recurring-policy sharing have merged implementations and focused tests. | Complete cross-feature qualification, remaining raw/result-access grant cases and upgrade role re-production remain. Policy-packet grants in PR #103 are unmerged. Its named creator/manager/grant and privacy workflow now passes; this does not establish complete cross-feature qualification. |
| Capture profiles, guidance, history and repeat | Typed versioned packet/syscall planning and manual network-header execution are merged. Recent context captures, settings and Collect again passed an installed share workflow ([PR #76](https://github.com/phihos/asservat/pull/76)). | General catalog publication/composition/execution, guidance and source-save repetition remain. Encrypted parameterized recording history in PR #103 is not installed-qualified; context history success does not establish recording-history availability. |
| Permission/privacy administration | Explicit and inherited permissions, access explanations, team/share controls and permission/retention impact previews are implemented. Installed context tests cover revocation, expiry, failed-cleanup charge retention and verified deletion; processing initialization and deletion supervision also exist. | Processing release, overdue/admin reporting, complete operational qualification, browser-session cleanup, managed-copy/backup lifetime closure and sustained availability remain. In-place upgrades have explicitly documented role-grant limitations. |
| Incident notification and recurrence investigation | Designed, with narrow context case/navigation components. | Trigger-to-case grouping, notification delivery, timelines, findings and recurrence comparison. |
| Small deployment alternatives | Local wrapping/signing/key-service components exist. | Installed internal accounts, local PKI lifecycle, bundled PostgreSQL/pgBackRest/evidence store and provider lifecycle qualification. |
| Recover, upgrade and operate production | Initial bootstrap, database-incarnation fencing and schema/image upgrade components have focused native evidence. Installed context tests exercise interrupted/resumed installation and lifecycle negatives. | Complete supported backup/restore, failover/partition and version-skew profiles, sustained operation, distributable verified artifacts and production acceptance remain. |

The [detailed baseline](../test/results/implementation-baseline-20261012/INVENTORY.md.txt)
records 17 capability groups and seven shared dependencies, with
[source hashes](../test/results/implementation-baseline-20261012/sources.json).
It is a dated evidence snapshot; later tracker entries supersede its transient
failure descriptions. These rows are deliberately not converted into a percentage.

## Homelab trial status

A source-built, context-only developer experiment can use an ordinary owned
homelab Kubernetes cluster without a node collector or disposable-node marker.
It requires external PostgreSQL, S3-compatible storage, OpenBao and Keycloak;
matching source-built, digest-pinned images accessible to the cluster; and the
[documented installer setup](installation/helm.md#optional-initial-bootstrap-checkpoint),
including separate credentials, identity and permission configuration, delegation
setup where needed, regional enrollment, and private-registry credentials only
when used. The default Helm install starts no services, but
`bootstrap.enabled: true` with `bootstrap.continuation.enabled: true` runs the
existing runtime continuation while `runtime.enabled` remains `false`.
`runtime.enabled: true` is still rejected.

Packet collectors remain [disposable-test-host only](installation/helm.md#node-collector-test-hosts-only);
do not enable them on ordinary homelab nodes. Internal users and the bundled
small-deployment profile remain unfinished, and no supported release or alpha
scope is established. The browser recording-history failure and intermittent
availability limits below remain relevant limitations, not prerequisites for a
context-only experiment. Such an experiment can precede the full feature set
while retaining its authority, custody and privacy checks and all accepted
first-release requirements. No calendar date is established.

PR #104 fixes HTTP completion for owned query replies during joined cleanup;
its local transport checks, pre-merge CI and automatic main CI passed. It does
not fix recording-history/settings replies, which use the unowned path, or
establish an installed query workflow. The separate working candidate's packet
clock correction and real SQL qualification of failure diagnostics are component
results; installed recording history remains unqualified.

Frozen PR #103 candidate `c328a5af` passed all fifteen CI jobs
and fresh review. Its installed campaign produced two passes and one failure:

- [Policy 40842273194](https://github.com/phihos/asservat/actions/runs/40842273194)
  passed creator disable/readback, sponsoring-manager continuation, grant
  replacement/revocation, publication, authenticated download and actual
  ACK/header/no-payload verification. The retained PCAPNG is 2,660 bytes with
  24 packets. This qualifies the named finite workflow, not ongoing recording.
- [Paced 40842297608](https://github.com/phihos/asservat/actions/runs/40842297608)
  passed matching 8,388,476-byte whole bodies, a 6.518-second paced read, resumed
  ranges, original owner/window, renewal, three key slots, final acknowledgement
  and Complete under the explicit 200m synthetic target profile.
- [History 40842283977](https://github.com/phihos/asservat/actions/runs/40842283977)
  passed initial capture/native verification and storage acknowledgements, then
  failed at the built React driver's history-list response: HTTP 200 with an
  unclassifiable reply. Retrieval/parsing failure and malformed reply status are
  not distinguished yet. Browser settings/repeat remains unqualified. Ten demand
  refreshes succeeded in this attempt; earlier intermittent cold failures remain
  unexplained.

Root verified actual exits 0/0/1, all 3,405 canonical source hashes, unchanged
sources, removed scratch and clean teardown. PR #103 remains draft. Earlier
failures and local reproductions remain in the progress record. These named
passes do not establish repeatable homelab readiness. There is no dependable
calendar ETA or overall completion percentage. The next forecasting checkpoint
is a stable, repeatable supported workflow rather than another component count.

The later diagnostic-only `80b9a000` passed CI/review, but
[history run 40849033981](https://github.com/phihos/asservat/actions/runs/40849033981)
failed earlier at storage readiness, before capture or the browser body checks.
A demand refresh reported guarded-read/claim/post refusal after 2.27 seconds;
the precise cause remains unresolved. Root verified exit 1, all 3,407 source
hashes and clean teardown. No automatic retry is queued.

The later owner-read correction `80c826fe` passed all fifteen CI jobs and fresh
review. Its single
[history run 40863490795](https://github.com/phihos/asservat/actions/runs/40863490795)
reached successful initial capture and complete diagnostics/history-list replies,
then failed reading the HTTP-200 settings response body in the browser driver.
Settings/edit/repeat remains unqualified; this is not evidence of malformed JSON
or an established transport cause. Root verified actual exit 1, all 3,408 source
hashes, unchanged sources and clean teardown. No automatic retry is queued.

The diagnostic-only `960a28bc` passed CI and fresh review, but its single
[history run 40869970360](https://github.com/phihos/asservat/actions/runs/40869970360)
failed earlier at storage readiness, before capture or the browser. Its matching
thirty-second binding had expired despite a current refresh demand; the producer
cause is not established. Root verified exit 1, all 3,408 source hashes, unchanged
sources and clean teardown. The new browser failure classifier was not reached.
Both readiness and settings delivery remain under investigation; no retry is
queued. These recording-path failures do not prohibit the limited context-only
experiment described above or establish a supported release date.

The later composed `08c0a804` passed all fifteen CI jobs and fresh review.
[History run 40891973567](https://github.com/phihos/asservat/actions/runs/40891973567)
accepted the initial capture, acknowledged four storage copies and successfully
read browser history and settings. Its edited preview returned a complete
`ParametersUnavailable` error. Repeat remains unqualified; the earlier settings
body failure was not reproduced or shown repaired. Root verified exit 1, all
3,412 canonical hashes, unchanged sources and clean teardown. No retry is queued.

## Next product milestone and forecasting basis

S-02's established context path and remaining acceptance work provide the
baseline: use an installed hub to select
an authorized workload in either of two clusters, preview/request context through
browser and MCP, collect and publish encrypted evidence, inspect/download it, then
verify denial on expiry/revocation and deletion of managed copies. Authority and
capacity must come from product-provisioned accepted sources, not fixture seeding.

Native107 (2026-10-24, [record](../test/results/resumed-c62e02ac-native107/README.md))
passes the named core S-02 journey in two workload clusters through one hub: browser and MCP
preview/request/inspection/download with reply parity, duplicate and conflicting idempotency,
Range resume, catalog minimization, an unrelated principal refused exactly as for absent
objects, Stop, Deny revocation, expiry refusal, a failed cleanup that retains its charges and
verified deletion; the second cluster completes capture, publication and native download.
Still not installed-qualified, against the
[S-02 exit](architecture/implementation-slices.md#s-02-exit-in-detail):

- hub disconnect/reconnect importing a committed result (documented limitation, ADR-223:
  a lost regional completion reply is not imported and the collection is never repeated);
- object/KMS failure states in the installed run: object-store failure reports
  `Indeterminate`/`StorageOutcomeUnconfirmed` and exhausted capacity `CapacityUnavailable`
  (component tests); a key-service failure before the start stays Pending until the deadline
  marks it Indeterminate.

A lost target is installed-qualified in [native109](../test/results/resumed-c62e02ac-native109/README.md):
a request for a deleted reviewed Pod returns `TargetGone`; a started capture records
`TargetGone` or `Denied` ([ADR-225](decisions/225-context-capture-failure-causes.md)).

Future forecasts must use bounded deliverables with explicit implementation,
integration and qualification work; account for dependencies and shared foundations;
and compare estimates with measured delivery of similar completed workflows.
Report scope changes and uncertainty explicitly. Until that baseline supports a
forecast, report completed outcomes, current failures and the next acceptance test.
