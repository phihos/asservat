# ADR disposition index

[Whole-project assessment](README.md). Labels are recommendations, not implementation status or a completion score.

Coverage: 210 records, 2310 question answers. Missing catalog numbers: 142, 143, 154.

| Disposition | ADRs |
| --- | ---: |
| keep | 76 |
| simplify | 121 |
| defer | 4 |
| superseded | 8 |
| remove | 1 |

| ADR | Decision | Recommendation |
| --- | --- | --- |
| [ADR-001](adr-001-095.md#adr-001) | Product identity and baseline exclusions | **keep** |
| [ADR-002](adr-001-095.md#adr-002) | Central multi-cluster first release | **keep** |
| [ADR-003](adr-001-095.md#adr-003) | Expiring policy approval | **keep** |
| [ADR-004](adr-001-095.md#adr-004) | Kubernetes-only hub state | **superseded** |
| [ADR-005](adr-001-095.md#adr-005) | Explicit sharing within one organization | **keep** |
| [ADR-006](adr-001-095.md#adr-006) | Go services and narrow Rust crash helper | **keep** |
| [ADR-007](adr-001-095.md#adr-007) | Lightweight specification workflow | **simplify** |
| [ADR-008](adr-001-095.md#adr-008) | Policy, recipe and capture resource separation | **simplify** |
| [ADR-009](adr-001-095.md#adr-009) | External reference dependency profile | **superseded** |
| [ADR-010](adr-001-095.md#adr-010) | Packet header sanitization before retention | **keep** |
| [ADR-011](adr-001-095.md#adr-011) | Isolated analysis of inert target files | **simplify** |
| [ADR-012](adr-001-095.md#adr-012) | Structured server-side debugger operations | **simplify** |
| [ADR-013](adr-001-095.md#adr-013) | License and contribution baseline | **defer** |
| [ADR-014](adr-001-095.md#adr-014) | Security and privacy in the first vertical slice | **simplify** |
| [ADR-015](adr-001-095.md#adr-015) | Runtime profiles as first-class evidence | **keep** |
| [ADR-016](adr-001-095.md#adr-016) | One organization per installation | **keep** |
| [ADR-017](adr-001-095.md#adr-017) | Automated Kubernetes permission inheritance | **simplify** |
| [ADR-018](adr-001-095.md#adr-018) | Kubernetes-only permission authoring | **keep** |
| [ADR-019](adr-001-095.md#adr-019) | Low-effort operator and developer workflows | **keep** |
| [ADR-020](adr-001-095.md#adr-020) | Administrator retention maxima | **simplify** |
| [ADR-021](adr-001-095.md#adr-021) | Storm control and storage isolation | **simplify** |
| [ADR-022](adr-001-095.md#adr-022) | Capture-time and recurring-policy sharing | **simplify** |
| [ADR-023](adr-001-095.md#adr-023) | PostgreSQL hub transactional state | **keep** |
| [ADR-024](adr-001-095.md#adr-024) | Immutable creator and multiple managing teams | **keep** |
| [ADR-025](adr-001-095.md#adr-025) | Packet filters, dynamic peers and segmented rings | **keep** |
| [ADR-026](adr-001-095.md#adr-026) | Observe all authorized replicas, cap collection separately | **keep** |
| [ADR-027](adr-001-095.md#adr-027) | Finite administrator-selected policy approval periods | **simplify** |
| [ADR-028](adr-001-095.md#adr-028) | Whole-pod public scope | **keep** |
| [ADR-029](adr-001-095.md#adr-029) | Separate submission, execution and sharing identities | **simplify** |
| [ADR-030](adr-001-095.md#adr-030) | Deterministic guided diagnostics | **keep** |
| [ADR-031](adr-001-095.md#adr-031) | Capture history and repeat | **keep** |
| [ADR-032](adr-001-095.md#adr-032) | Reusable versioned capture profiles | **keep** |
| [ADR-033](adr-001-095.md#adr-033) | Bounded syscall evidence | **keep** |
| [ADR-034](adr-001-095.md#adr-034) | Separate ongoing recording from on-trigger actions | **keep** |
| [ADR-035](adr-001-095.md#adr-035) | Combined impact and data-handling assessment | **keep** |
| [ADR-036](adr-001-095.md#adr-036) | Encrypted scratch for offline analysis | **simplify** |
| [ADR-037](adr-001-095.md#adr-037) | Exact target and stopped-source correctness | **keep** |
| [ADR-038](adr-001-095.md#adr-038) | Save existing recordings now | **keep** |
| [ADR-039](adr-001-095.md#adr-039) | Shared console, domain and interface design | **superseded** |
| [ADR-040](adr-001-095.md#adr-040) | Approved live views of existing sources | **keep** |
| [ADR-041](adr-001-095.md#adr-041) | Minimalist console design system | **keep** |
| [ADR-042](adr-001-095.md#adr-042) | Modular implementation architecture | **simplify** |
| [ADR-043](adr-001-095.md#adr-043) | Internal authenticated control and stable effects | **simplify** |
| [ADR-044](adr-001-095.md#adr-044) | Native download for every evidence type | **simplify** |
| [ADR-045](adr-001-095.md#adr-045) | One approval for collection and result access | **keep** |
| [ADR-046](adr-001-095.md#adr-046) | React and TypeScript console served by Go | **keep** |
| [ADR-047](adr-001-095.md#adr-047) | Reuse established protocol and storage libraries | **keep** |
| [ADR-048](adr-001-095.md#adr-048) | Framed encrypted artifact layout | **keep** |
| [ADR-049](adr-001-095.md#adr-049) | Bounded access-token and eligibility profile | **simplify** |
| [ADR-050](adr-001-095.md#adr-050) | Durable permission assignments and audited acceptance | **simplify** |
| [ADR-051](adr-001-095.md#adr-051) | Internal peer certificate profile | **simplify** |
| [ADR-052](adr-001-095.md#adr-052) | Finite signing attempts and audited activation | **simplify** |
| [ADR-053](adr-001-095.md#adr-053) | Explicit Keycloak access profile | **keep** |
| [ADR-054](adr-001-095.md#adr-054) | Native preparation metadata and HTTP resume | **keep** |
| [ADR-055](adr-001-095.md#adr-055) | Monotonic retention cutoffs and lifecycle audit | **simplify** |
| [ADR-056](adr-001-095.md#adr-056) | Complete retention watch history before readiness | **simplify** |
| [ADR-057](adr-001-095.md#adr-057) | Pinned retention topology | **keep** |
| [ADR-058](adr-001-095.md#adr-058) | Official Helm installation | **keep** |
| [ADR-059](adr-001-095.md#adr-059) | Team automation authority separate from human SSO | **keep** |
| [ADR-060](adr-001-095.md#adr-060) | Server-side browser sessions | **keep** |
| [ADR-061](adr-001-095.md#adr-061) | Current protected browser settings | **simplify** |
| [ADR-062](adr-001-095.md#adr-062) | Post-persistence policy submission signatures | **simplify** |
| [ADR-063](adr-001-095.md#adr-063) | Small deployment alternatives | **keep** |
| [ADR-064](adr-001-095.md#adr-064) | Versioned local crypto providers | **keep** |
| [ADR-065](adr-001-095.md#adr-065) | Isolated local key-service boundary | **simplify** |
| [ADR-066](adr-001-095.md#adr-066) | Download-bound unwrap accounting | **simplify** |
| [ADR-067](adr-001-095.md#adr-067) | Protected local-key lifecycle observations | **simplify** |
| [ADR-068](adr-001-095.md#adr-068) | Kubernetes-bound acquisition-worker proof | **simplify** |
| [ADR-069](adr-001-095.md#adr-069) | Durable download-worker dispatch and retirement | **simplify** |
| [ADR-070](adr-001-095.md#adr-070) | Accepted worker configuration and rollout fencing | **simplify** |
| [ADR-071](adr-001-095.md#adr-071) | Audited worker credentials and renewal | **simplify** |
| [ADR-072](adr-001-095.md#adr-072) | Private worker credential channel | **simplify** |
| [ADR-073](adr-001-095.md#adr-073) | Worker startup and original-template cleanup | **keep** |
| [ADR-074](adr-001-095.md#adr-074) | Process-local active worker-request ownership | **simplify** |
| [ADR-075](adr-001-095.md#adr-075) | SQL locator for live worker owner | **simplify** |
| [ADR-076](adr-001-095.md#adr-076) | Exact hub owner discovery and TLS identity | **simplify** |
| [ADR-077](adr-001-095.md#adr-077) | Protected hub owner configuration | **simplify** |
| [ADR-078](adr-001-095.md#adr-078) | Durable owner configuration acceptance | **simplify** |
| [ADR-079](adr-001-095.md#adr-079) | Purpose-separated hub owner certificate issuance | **simplify** |
| [ADR-080](adr-001-095.md#adr-080) | Protect the private hub workload namespace | **simplify** |
| [ADR-081](adr-001-095.md#adr-081) | Prove hub owner enrollment before readiness | **simplify** |
| [ADR-082](adr-001-095.md#adr-082) | Durable hub process enrollment | **simplify** |
| [ADR-083](adr-001-095.md#adr-083) | Current authentication of an enrolled hub peer | **simplify** |
| [ADR-084](adr-001-095.md#adr-084) | Process-owned hub credentials and renewal | **keep** |
| [ADR-085](adr-001-095.md#adr-085) | Private owner enrollment receiver | **superseded** |
| [ADR-086](adr-001-095.md#adr-086) | Outbound owner enrollment transfer | **superseded** |
| [ADR-087](adr-001-095.md#adr-087) | Live owner cancellation through worker delivery | **simplify** |
| [ADR-088](adr-001-095.md#adr-088) | Owner startup readiness and runtime composition | **simplify** |
| [ADR-089](adr-001-095.md#adr-089) | Multi-cluster worker routing and exact issuer selection | **keep** |
| [ADR-090](adr-001-095.md#adr-090) | Protected owner deployment inputs and rotating credentials | **simplify** |
| [ADR-091](adr-001-095.md#adr-091) | Protected fleet and owner configuration reconciliation | **simplify** |
| [ADR-092](adr-001-095.md#adr-092) | Independent source admission probes in the private hub namespace | **simplify** |
| [ADR-093](adr-001-095.md#adr-093) | Bounded scheduling permission inside the private hub namespace | **keep** |
| [ADR-094](adr-001-095.md#adr-094) | Native hub-worker credentials and workload | **keep** |
| [ADR-095](adr-001-095.md#adr-095) | Protected hub workload garbage collection | **keep** |
| [ADR-096](adr-096-164.md#adr-096) | Database incarnation fence before recovery activation | **keep** |
| [ADR-097](adr-096-164.md#adr-097) | One-use installation witness | **simplify** |
| [ADR-098](adr-096-164.md#adr-098) | Audited first-installation activation | **simplify** |
| [ADR-099](adr-096-164.md#adr-099) | Protected initial-installer execution | **simplify** |
| [ADR-100](adr-096-164.md#adr-100) | Temporary initial-installation SQL credentials | **simplify** |
| [ADR-101](adr-096-164.md#adr-101) | Protect installation staging before workload identities exist | **simplify** |
| [ADR-102](adr-096-164.md#adr-102) | Persist bounded installation creation intent | **simplify** |
| [ADR-103](adr-096-164.md#adr-103) | Durable manual context previews and accepted retries | **keep** |
| [ADR-104](adr-096-164.md#adr-104) | Regional Kubernetes API context execution | **keep** |
| [ADR-105](adr-096-164.md#adr-105) | Durable, authorized context capture progress | **simplify** |
| [ADR-106](adr-096-164.md#adr-106) | Regional API context start and completed-result provenance | **simplify** |
| [ADR-107](adr-096-164.md#adr-107) | Atomic resolution of an uncertain manual capture request | **keep** |
| [ADR-108](adr-096-164.md#adr-108) | back context control records per workload | **simplify** |
| [ADR-109](adr-096-164.md#adr-109) | Published context cases and ordinary navigation | **keep** |
| [ADR-110](adr-096-164.md#adr-110) | Bounded public operation intent and result audit | **simplify** |
| [ADR-111](adr-096-164.md#adr-111) | Positive context writer completion and audited deletion | **simplify** |
| [ADR-112](adr-096-164.md#adr-112) | Healthy operation audit retirement and backed history | **simplify** |
| [ADR-113](adr-096-164.md#adr-113) | Whole native responses with bounded accounting windows | **simplify** |
| [ADR-114](adr-096-164.md#adr-114) | Browser refresh owned by an active download | **simplify** |
| [ADR-115](adr-096-164.md#adr-115) | Overdue original operation-audit erasure | **simplify** |
| [ADR-116](adr-096-164.md#adr-116) | purpose-specific regional native context exchange | **simplify** |
| [ADR-117](adr-096-164.md#adr-117) | Resume fixed declarative setup after a lost create reply | **simplify** |
| [ADR-118](adr-096-164.md#adr-118) | Retain initial private material and read historical completion | **simplify** |
| [ADR-119](adr-096-164.md#adr-119) | Public ordinary context downloads and prepaid Stop | **simplify** |
| [ADR-120](adr-096-164.md#adr-120) | Explicit gated installation preparation and original credential binding | **simplify** |
| [ADR-121](adr-096-164.md#adr-121) | Explicit native acquisition worker startup | **keep** |
| [ADR-122](adr-096-164.md#adr-122) | Separate private native owner listener | **simplify** |
| [ADR-123](adr-096-164.md#adr-123) | Typed initial installation inputs and one-use handover | **simplify** |
| [ADR-124](adr-096-164.md#adr-124) | Retire prepaid Stop obligations with positive writer proof | **simplify** |
| [ADR-125](adr-096-164.md#adr-125) | Spend a bounded allowance before operation-certificate verification | **simplify** |
| [ADR-126](adr-096-164.md#adr-126) | Bind connector identity to automatic process enrollment and bounded renewal | **simplify** |
| [ADR-127](adr-096-164.md#adr-127) | Current processing decisions and complete native placement | **simplify** |
| [ADR-128](adr-096-164.md#adr-128) | Original installation provider credentials and projection | **simplify** |
| [ADR-129](adr-096-164.md#adr-129) | Original installation handover and healthy retirement | **simplify** |
| [ADR-130](adr-096-164.md#adr-130) | Separate bounded first-installation schema administration | **simplify** |
| [ADR-131](adr-096-164.md#adr-131) | Produce original installation pins from trusted static inputs | **simplify** |
| [ADR-132](adr-096-164.md#adr-132) | Atomically backed capture-intent persistence | **simplify** |
| [ADR-133](adr-096-164.md#adr-133) | Close managed setup copies after positive original retirement | **simplify** |
| [ADR-134](adr-096-164.md#adr-134) | Explicit continuation of an accepted capture | **keep** |
| [ADR-135](adr-096-164.md#adr-135) | live outbound regional API context start | **simplify** |
| [ADR-136](adr-096-164.md#adr-136) | First approved-context native HTTP composition | **simplify** |
| [ADR-137](adr-096-164.md#adr-137) | Package the fixed initial installer with Helm | **simplify** |
| [ADR-138](adr-096-164.md#adr-138) | compose public context endpoints through one audited backend | **keep** |
| [ADR-139](adr-096-164.md#adr-139) | Share the accepted native port with live context start | **keep** |
| [ADR-140](adr-096-164.md#adr-140) | Protected producers for installed public runtime | **simplify** |
| [ADR-141](adr-096-164.md#adr-141) | Protected capacity production and managed renewal | **simplify** |
| [ADR-144](adr-096-164.md#adr-144) | Current cluster-local observation delegation | **simplify** |
| [ADR-145](adr-096-164.md#adr-145) | Independent capacity admission probe | **simplify** |
| [ADR-146](adr-096-164.md#adr-146) | Check prepaid processing coverage before collection | **keep** |
| [ADR-147](adr-096-164.md#adr-147) | Standard owner provider authentication | **simplify** |
| [ADR-148](adr-096-164.md#adr-148) | One public projection enforcement interval | **keep** |
| [ADR-149](adr-096-164.md#adr-149) | Fresh provider-installed worker and owner pair | **simplify** |
| [ADR-150](adr-096-164.md#adr-150) | Operation-owned native observation proof | **simplify** |
| [ADR-151](adr-096-164.md#adr-151) | Required versions for initial installation audit | **keep** |
| [ADR-152](adr-096-164.md#adr-152) | Current retention audit receipts | **keep** |
| [ADR-153](adr-096-164.md#adr-153) | Bind connector enrollment and signing to one native operation | **simplify** |
| [ADR-155](adr-096-164.md#adr-155) | Unchanged fleet observation persistence contention | **superseded** |
| [ADR-156](adr-096-164.md#adr-156) | Finite owner configuration audit epochs | **defer** |
| [ADR-157](adr-096-164.md#adr-157) | Separate protected observation dial ports from serving identity | **keep** |
| [ADR-158](adr-096-164.md#adr-158) | Owner startup preflight before recovery locking | **keep** |
| [ADR-159](adr-096-164.md#adr-159) | Complete owner projection preflight across the SQL lock | **keep** |
| [ADR-160](adr-096-164.md#adr-160) | Purpose-separated context service assembly | **simplify** |
| [ADR-161](adr-096-164.md#adr-161) | Separate fleet freshness from restrictive authority locks | **keep** |
| [ADR-162](adr-096-164.md#adr-162) | Read-only finalization of original owner projection effects | **simplify** |
| [ADR-163](adr-096-164.md#adr-163) | original-work transport observation lease | **keep** |
| [ADR-164](adr-096-164.md#adr-164) | Passive convergence of the original owner launch receipt | **keep** |
| [ADR-165](adr-165-213.md#adr-165) | Original observation capability selection | **simplify** |
| [ADR-166](adr-165-213.md#adr-166) | Bounded streaming custody for larger native outputs | **keep** |
| [ADR-167](adr-165-213.md#adr-167) | Phase-bounded context download continuation | **simplify** |
| [ADR-168](adr-165-213.md#adr-168) | Rotating cluster enrollment credential with outbound-only connectivity | **keep** |
| [ADR-169](adr-165-213.md#adr-169) | Delegated regional lifecycle channel | **simplify** |
| [ADR-170](adr-165-213.md#adr-170) | Federation compartment for connector-facing hub duties | **simplify** |
| [ADR-171](adr-165-213.md#adr-171) | Hub-run context execution with delegated regional operations | **keep** |
| [ADR-172](adr-165-213.md#adr-172) | Delegated owner discovery and authentication for regional exchanges | **simplify** |
| [ADR-173](adr-165-213.md#adr-173) | Work-scoped regional process observation | **keep** |
| [ADR-174](adr-165-213.md#adr-174) | Regional context-start composition in the connector process | **superseded** |
| [ADR-175](adr-165-213.md#adr-175) | Capacity account token by admitted, Pod-bound TokenRequest | **simplify** |
| [ADR-176](adr-165-213.md#adr-176) | Artifact keys through the local key service with attempt-scoped wrap authority | **simplify** |
| [ADR-177](adr-165-213.md#adr-177) | Per-purpose logins under a process-wide SQL connection governor | **simplify** |
| [ADR-178](adr-165-213.md#adr-178) | Delegated connector source on the context-start exchange | **simplify** |
| [ADR-179](adr-165-213.md#adr-179) | Outbound-only scope of the first installed investigation profile | **keep** |
| [ADR-180](adr-165-213.md#adr-180) | hub-api public composition and its protected inputs | **simplify** |
| [ADR-181](adr-165-213.md#adr-181) | Asynchronous publication in a dedicated verifier process | **keep** |
| [ADR-182](adr-165-213.md#adr-182) | Promoting the installed owner to native backend and public layers | **simplify** |
| [ADR-183](adr-165-213.md#adr-183) | Installer runtime continuation | **simplify** |
| [ADR-184](adr-165-213.md#adr-184) | Promoted owner on its first launch | **simplify** |
| [ADR-185](adr-165-213.md#adr-185) | Public sources and the cluster catalog | **simplify** |
| [ADR-186](adr-165-213.md#adr-186) | Operation-scoped public role proof | **simplify** |
| [ADR-187](adr-165-213.md#adr-187) | Replay after the guard bridge | **simplify** |
| [ADR-188](adr-165-213.md#adr-188) | Configuration role proof after the SQL locks and the bridge | **simplify** |
| [ADR-189](adr-165-213.md#adr-189) | Installed permission stream | **keep** |
| [ADR-190](adr-165-213.md#adr-190) | Capacity readiness around the promoted owner launch | **simplify** |
| [ADR-191](adr-165-213.md#adr-191) | Worker projection writes under one retained bracket | **keep** |
| [ADR-192](adr-165-213.md#adr-192) | Capacity readiness before download paths | **superseded** |
| [ADR-193](adr-165-213.md#adr-193) | Installed federation and regional cluster enrollment | **simplify** |
| [ADR-194](adr-165-213.md#adr-194) | Promoted owner inputs | **simplify** |
| [ADR-195](adr-165-213.md#adr-195) | Installed hub retention source | **simplify** |
| [ADR-196](adr-165-213.md#adr-196) | Regional cluster join | **simplify** |
| [ADR-197](adr-165-213.md#adr-197) | Regional capacity | **simplify** |
| [ADR-198](adr-165-213.md#adr-198) | Installed key service | **keep** |
| [ADR-199](adr-165-213.md#adr-199) | One source read at each end of the executor proof | **keep** |
| [ADR-200](adr-165-213.md#adr-200) | On-demand capacity refresh | **simplify** |
| [ADR-201](adr-165-213.md#adr-201) | eBPF CPU profiles for every runtime | **defer** |
| [ADR-202](adr-165-213.md#adr-202) | Public API exposure | **keep** |
| [ADR-203](adr-165-213.md#adr-203) | Installed publisher | **keep** |
| [ADR-204](adr-165-213.md#adr-204) | Installed native downloads | **simplify** |
| [ADR-205](adr-165-213.md#adr-205) | Installed context deletion | **keep** |
| [ADR-206](adr-165-213.md#adr-206) | Bounded approved pod-status projection reads | **defer** |
| [ADR-207](adr-165-213.md#adr-207) | One native proof bracket for context-start setup | **simplify** |
| [ADR-208](adr-165-213.md#adr-208) | Opening limiter for context-start Kubernetes clients | **simplify** |
| [ADR-209](adr-165-213.md#adr-209) | Two context-start standbys per hub owner | **remove** |
| [ADR-210](adr-165-213.md#adr-210) | Installed processing changes by a privacy operator | **simplify** |
| [ADR-211](adr-165-213.md#adr-211) | Return a completed target query to its original standby interval | **keep** |
| [ADR-212](adr-165-213.md#adr-212) | Remaining interval before one-use API preparation | **simplify** |
| [ADR-213](adr-165-213.md#adr-213) | Storage readiness at consumption | **simplify** |
