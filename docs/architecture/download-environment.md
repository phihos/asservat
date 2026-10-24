# Current processing and download environment

[ADR-127](../decisions/127-current-processing-and-download-placement.md) separates protected deployment/client policy from durable processing decisions. This composition belongs to existing C-03 ordinary authorization and C-15 privacy; it introduces no alternate permission evaluator.

`CurrentDownloadEnvironment` takes an already-authorized `ContextDownloadEvidence` and current principal. It resolves the protected policy, current recovery and SQL processing state, then independently rechecks all three after blocking work. The returned proof retains the earliest original identity/catalog/access/deletion/source/recovery/caller deadline and never exceeds five seconds. Empty permitted sets deny. A client identity allowlist alone does not provide disclosure permission.

[ADR-214](../decisions/214-bounded-download-policy-observation.md) changes the
installed download policy reader to share one completed protected observation for
at most 60 seconds from its original read start. The two policy lookups normally
reuse that same observation; every caller still selects its exact allowed path.
Current recovery and processing reads, dynamic proof bounds and original caller
deadlines remain unchanged. Refresh failures cannot reuse an expired observation.
This download-only view does not authorize processing administration: the raw
source and operator/capacity policy checks retain their five-second contract.

The private `download-environment.json` document is bounded to 128 KiB and closed by [its schema](../../specs/contracts/download-environment.schema.json). The Kubernetes source uses the existing native ConfigMap admission protection, independently pinned object/namespace/policy/binding identities, denied non-administrator probe, exact two reads and final guard. Complete paths are separately supplied by accepted installation composition; the ConfigMap may permit/remove one, but cannot invent a worker profile, hub pool or processing location. The source does not accept a recovery transition or a backend qualification.

`ProcessingConfiguration` records independently accepted finite business/history and release-audit backing; `ProcessingChanges` owns explicit current privacy-operator decisions. `ProcessingReads` only reads initialized durable decisions. Source/configuration, decision, audit writer and independent acknowledgement use separate credentials. A captured artifact's immutable projection is created inside verified catalog publication. There is no allowing lineage backfill. The bounded reader follows at most 64 nodes, 16 parents each and 1,024 rules; missing nodes, cycles, unsupported origins and incomplete state deny. Exact artifact and workload/original-acquisition-time rules cover current and future matching artifacts immediately at read time.

SQL mutation order is recovery, permission root, processing root and exact rule/decision. Before locking an acknowledged audit row, apply also locks the dedicated processing pool, matching journal replay; nested root checks cannot invert that order. Release audit admission locks its dedicated pool and reads the exact prepared business state without reverse business-row locks. Its human actor and original request remain immutable. The audit pair says prepared/effect-unknown; final current rights and SQL CAS determine the outcome. At most sixteen original decision attempts belong to each rule for its entire retained history; a failed restriction cannot consume the final reserved release attempt. Unknown audit writes remain charged. Private release policy has its own backed lane, provider clients and qualified lifecycle; normal audit exhaustion cannot consume that reserve.

Every lineage, rule and decision retains its own immutable coverage/retirement dates. Renewing installation backing supplies future capacity and cannot extend an older row. Administrative expiry never removes a restriction: the reader continues to apply it, and publishing later matching evidence beyond the retained coverage is unavailable until qualified reconciliation. The current private decision protocol cannot renew an expired rule or infer release from its date.

Current download effects re-evaluate the proof under the existing permission lock, after recovery and before acquisition or delivery. Worker dispatch compares accepted configuration and acquisition cluster. Native worker/connector/hub admission compares the actual authenticated identities and accepted route, including store, target and current processing state. The hub remains unable to unwrap artifact keys. Terminal protocol closure emits no evidence and retains its existing separate checks.

SQL credentials for worker enrollment, certificate activation and active-request
owner claims also require read-only access to `processing_root`,
`context_processing` and `processing_rule`: those effects call the same current
download fence. That read access cannot initialize, release, modify or delete
processing state. Historical audit acknowledgements and passive owner-locator
lookups do not acquire these current-effect reads. The separately credentialed
native regressions exercise both the required reads and denied mutations.

Ordinary `get_case` resolves current eligibility and retained audience before existence-sensitive artifact processing reads, and repeats the processing check before response. It discloses no native filename or native checksum. An absent optional proof supports only historical decoding; production live effects do not have a legacy permit fallback.

An unrelated publish/passive reservation cannot change an existing state digest. Unrelated restrictive decisions conservatively invalidate the installation sequence; no output occurs during fresh authorization. The existing session and native range resume remain available under their original limits if the artifact is still permitted. Actual artifact/ancestor restriction stops output within the current lease; it never triggers another capture or grants replacement capacity.

This stage does not provide business-row retirement, restore approval, installation/source acceptance, a privacy-operator public endpoint, or broader analysis/share services. Those paths may not infer unrestricted state. All identifying SQL/backup obligations remain charged until separately qualified retirement exists. Unit/component and actual provider results must be recorded separately; source-only fixture hooks are not qualification.


## Qualification boundary

The isolated source candidate passes affected Go race tests and vet, SQLc parsing/generation, the Go package architecture checker through its source overlay, the existing JSON Schema validator with URI/date-time checks, and maximum private-command tests under the unchanged 640 KiB limit. The native frame and actual process-owned hub identity regressions failed against the earlier code before their fixes. Local TLS/source tests use explicit synthetic accepted pins; they are not Kubernetes admission qualification.

The integrated SQL50 real-service run passes both `processing-restrictions-before-publication-and-prepaid-release` and `processing-restriction-fences-prepaid-native-output`, alongside connector renewal regressions under `TestContextAdmissionWithRealServices`. It uses actual SQL and encrypted audit with synthetic accepted operator/backing inputs. The cases include immutable-date renewal, full-normal-pool release, same-key replay, role denial, post-lock expiry, pool/audit lock order, blocking a prepaid batch and resuming that same charged batch after release. Diagnostic runs exposed an audit timestamp representation conflict and a connector fixture connection leak; retained failing/passing evidence is in [implementation progress](../implementation-progress.md). The time correction preserves exact instants and all other audit fields; fixture closure preserves the existing database connection limit. This does not qualify installed policy/backing provisioning, a full HTTP transfer or production recovery. SQLc alone cannot validate PL/pgSQL execution or establish deadlock freedom.
