# Fixed trusted bootstrap phases

This ADR-131 continuation composes the concrete bootstrap producer, initial schema command, preparation supervisor and manager retirement through fixed private commands. The owned native fixture now qualifies the complete compiled command chain and setup-free completed replay. Official Helm runner packaging remains separate work; these commands do not enable public services or chart runtime.

## Inputs and order

`initial-bootstrap` reads `/run/asservat/initial-bootstrap/bootstrap.json` and the current Kubernetes administrator token. For a positively fresh installation, the installer selects persisted `asservat-initial-bootstrap/v3`, including [positive managed-copy closure](initial-bootstrap-copy-closure.md). Operators do not supply dynamic pins or a replay mode. Exact retained v2/v3 metadata or a complete independently protected original pre-seed prelude preserves that original version and its pins. Missing seed alone, partial/unknown state or an existing v1 seed cannot authorize creation or silent upgrade. The earlier measured command-chain result below used v2; v3 closure needs its own native qualification.

Before any broad seed or setup-file read, the producer requests the seed as `application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1`, with no full-Secret fallback. A bounded once-set annotation identifies the original seed, installation/request, immutable public projection and exact passive-history Secret UID. Unsupported negotiation, malformed or replaced metadata, missing original history, and contradictory known state deny. If the locator is absent, both the preparation root and target namespace must still be absent before the ordinary original-seed path is considered; root existence or unknown lookup does not authorize recreation.

The fixed immutable `<name>-passive-history` Secret contains only the original SELECT-only history login and its public configuration/observation projections. Its ninth bounded create has an original operation ID persisted before POST and is capped by the original manager setup interval. Later exact receipt recovery may acknowledge an already created copy without another CREATE or a renewed interval. An uncertain reply or restart can only look up and verify that exact object. Acknowledging its UID/resourceVersion and publishing the metadata-only locator use one original seed CAS. Native admission forbids removal or replacement of a published locator and mutation/deletion of the history Secret. This bundle is committed before preparation-root creation or schema effects.

After exact current public pins and independent admission denial, the completed producer uses this history-only bundle to classify protected handover and independently read activation history. A completed replay returns before loading `Secret.data` from the broad seed or opening manager, provider or SQL administrator inputs. These observations are bounded and checked after waits; concurrent completion does not retrospectively turn an earlier active operation into a passive one. The locator itself is historical routing, never current SQL/effect authority.

Only positively established first-creation absence requests explicit `provider-material.json`; other errors never imply absence or permission to substitute supplied material. SQL administrator credentials are opened only for unfinished original manager creation or independently justified first retirement.

The fixed dedicated Pod scratch mount is `/run/asservat/initial-bootstrap-work`. It may retain Kubernetes emptyDir permissions and must be a real tmpfs owned by root or the current user with the current process group. Only the trusted sequential installation phases mount it. The product creates its fixed `projection` child with its current UID and mode `0700`; the child must be a real directory on tmpfs and is exclusively locked. Existing foreign, shared, aliased or non-tmpfs children fail without chmod/adoption. Later phases mount only `projection/schema` or `projection/preparer` subPaths. The scratch parent is not a private material directory. Fixed `schema` and `preparer` directories cannot be aliases. Writes use private files and atomic replacement within the owned directory; cancellation, invalid names, oversized inputs and concurrent producers fail. No arbitrary output path or private response is accepted. Both phases receive the immutable public deployment configuration, generated public observation projection and current administrator token. Only the preparer directory receives the exact retained passive-history login, plus the original manager login while active preparation remains possible. Completed passive classification removes a previous maintenance projection.

`initial-bootstrap-schema` mounts the schema directory at `/run/asservat/initial-schema`. It independently reads the protected original root and exact compiled schema bundle/head before opening `/run/asservat/initial-schema-private/postgres-ddl.json`. An unchanged completed schema skips DDL. This is a no-effect scheduling result: it does not attest current SQL readiness, clear recovery or authorize a post-restart activation. The active preparation loader and final SQL transaction independently consume the original schema incarnation binding. Missing, replaced or contradictory known state fails; no maintenance/provider login is mounted into this phase.

`initial-bootstrap-prepare` mounts the preparer directory at the existing fixed path and runs the existing supervisor. Its whole-install completed branch stays before maintenance/provider loading. An interruption after schema completion uses the read-only exact schema verifier before further effects; it does not repeat grants or manager readiness after legitimate creator memberships exist.

`initial-bootstrap-retire` is a separate ordered process after the preparation process and its owned pools have joined. **First actual retirement** independently verifies completed native handover and current activation history through the history-only bundle before reading the broad seed's original closure material. It then rechecks native cleanup/history, retains the original close claim and uses the separate trusted SQL administrator facet. Final completion requires the actual original manager's restricted privileges, terminated existing sessions and original-password denial. Only that positive closure can persist the once-set manager-retired annotation with the original completion time.

**Already-retired replay** reads metadata plus the history-only bundle, independently verifies the same protected completed handover/history, and returns before any broad seed or setup-credential read. Neither a timestamp passing nor an attempted SQL cleanup supplies the positive annotation. The seed's Closing field is not global credential revocation. Manager retirement and the later managed-private-copy deletion are distinct transitions.

## Current observation without private replay

`asservat-bootstrap-observation/v1` contains original public namespace, account, Role, binding, marker, token-anchor, admission-guard and immutable projection identities. It binds the accepted desired input and plan/projection digests. It contains no SQL passwords, issuer/storage credentials, seed-payload digest or target one-use credential.

Every phase constructs its concrete observer from that fixed projection. Before a fresh observation token is issued it checks the current exact public objects and administrator/guard. The restricted TokenRequest binds the original empty token-anchor Secret, audience and 600-second expiry. Actual self-identity and independent denial are checked before returning the credential, followed by final current public checks. The small empty public anchor is distinct from private source Secrets. An expired token can be replaced within a running phase or on passive restart without reading the private seed, adopting an identity or extending any original effect period.

The observer retains the original process cancellation and at most fifteen minutes, allows one active refresh and four conservatively spent attempts, and joins active work on Close. Refresh starts within thirty seconds of the credential expiry; it is not a periodic effect or a renewed policy lease. The cached token is an observation credential only: each downstream guard/effect retains its separate original at-most-five-second proof and cancellation checks. Retained sources deny after Close. Already returned token bytes and API authentication caches are not claimed erased or independently revoked by local closure; the owning phase closes its clients.

## Qualification and remaining work

The staged test sources cover exact no-effect schema decisions, current public observation, expiry/reopen, cancellation during the final blocking read, exclusive memory-directory ownership, fixed file limits, phase separation, exact metadata negotiation/no fallback, history-only replay, original receipt preservation and lost-create restart. The package handoff records which checks have actually run; new passive-history tests and command-chain qualification must not inherit results from an earlier source checkpoint. Passing local TLS tests use synthetic API responses and are not native admission evidence. The parent separately qualifies the actual API and SQL/provider compositions with frozen sources and owned cleanup.

Managed SQL/provider source Secret-copy deletion remains required. It needs original UID/resourceVersion, positive reader/writer/credential closure, completed handover and retained occupied names that cannot be recreated. Operator-owned originals and upstream credentials retain their existing ownership. Legacy v1/v2 retain those managed copies; successful manager retirement does not claim their deletion. Fresh v3 adds a separate original fifteen-minute closure claim, permanent name tombstone, exact UID/resourceVersion deletion and atomic immutable seed sanitization. The staged native v3 case must qualify this transition before claiming copy removal. Helm runner packaging remains unfinished.

The [owned real Kubernetes run](../../test/results/bootstrap-passive-native-after.log)
now verifies the v2 seed/guard/projection, exact recovery of a committed history
CREATE with lost reply, metadata-only passive reads, immutable locator and
history mutation denial. Its [terminal report](../../test/results/bootstrap-passive-native-after-check.log)
records unchanged sources and complete cleanup. The SQL manager receipt in
this API-only fixture is synthetic: it performs no SQL/provider effect and
proves no complete command-chain activation or retirement. The initial failed
run and the early provider-name validation correction remain recorded in
[implementation progress](../implementation-progress.md).

The subsequent [whole command-chain run](../../test/results/bootstrap-chain-native-first.log)
starts with an empty SQL database and executes the actual four commands in a
Restricted Pod. It qualifies native scratch/subPath composition, product-created
manager/schema, original activation Pod/image, independent encrypted audit and
positive manager retirement. A new runner repeats all phases after operator
setup files are removed and the supplied issuer token revoked; protected
identities/progress stay unchanged. Its [terminal report](../../test/results/bootstrap-chain-native-first-check.log)
records exit 0, unchanged sources and complete cleanup. Initial administrator
and upstream services are fixture inputs; no synthetic completion/activation
is supplied. Managed copy deletion, restore recovery and public service
installation remain outside this result.
