# Trusted bootstrap input producer

ADR-131 removes manually assembled dynamic pins from the installation prerequisite path. C-20 defines closed static desired input, explicit private provider material and a bounded private seed. Kubernetes and PostgreSQL adapters perform the actual creation and exact observation; no test authority or SQL success substitutes for native guard, protected state or independent activation history.

## Trust and fixed inventory

The selected bootstrap namespace is an explicit administrator trust entry, separate from the target namespace and selected by stable name. The producer observes its actual UID and Restricted policy. It creates only an observation service account, exact named get/update Role and binding, two public probe markers, and an immutable empty Secret token anchor before installing its exact compiled admission policy/binding. Administrator identity and actual independent dry-run denial are checked before the private seed or SQL effects. The continuity marker has only the exact independent probe's dry-run UPDATE exception; persistent mutation remains denied. A bounded 600-second observation token may be reacquired on later passive reopen and supplies no SQL/provider lifetime.

The private seed contains the accepted original IDs, static desired digest, distinct random SQL passwords, explicitly supplied provider material and eight fixed create slots: private progress, SQL material, provider material, continuity policy/binding, staging policy/binding, and immutable public deployment projection. A seed CREATE winner is reread before any subsequent effect. Original UID/resourceVersion CAS and immutable exact receipts prevent replacement/adoption. No arbitrary resource array, effect queue, credentials in ConfigMaps, secret-payload hashes or mutable Helm progress is added.

`InitialBootstrap.PrepareProjection` assembles and checks the requested fixed body before claiming its one original CREATE. A final admission policy still awaiting native type checking can therefore be observed again without consuming an unsent create. The acknowledged first claim may POST once; a persisted/unknown claim can only read its exact original object. A definite absence cannot mint another operation. Every live method retains the original caller/process cancellation and at-most-five-second deadline, including all final checks. Close joins its admitted work.

The immutable projection keeps original policy generation/UID and binding UID/resourceVersion even after handover legitimately retires staging. Reading that projection is not an active guard check or permission to rerun setup. The existing preparer selects its own independently protected passive history branch. No private password, issuer token or storage credential enters this projection.

## SQL manager and closure

`InitialSQLManager` consumes the concrete protected seed port and an explicitly supplied separate trusted SQL-administrator connection. Only the acknowledged fresh seed claim permits CREATE. The manager name is installation-derived; role/password/OID/attributes/comment/original 30-minute expiry must match on replay. SCRAM verifier generation reuses the existing maintained helper. There is no automatic ALTER PASSWORD, existing-role adoption or credential reissue. A post-schema replay permits only the exact compiled original grant union, never unrequested application authority.

`BeginManagerClose` checks the retained immutable projection and actual complete handover before retaining its irreversible original 30-second close claim. The supervisor must also join its owned preparation process/pool. `InitialSQLManager.Retire` independently reads the same positive activation record through ordinary protected history and SQL, preserves its original deadline, checks original database incarnation after locks, and restricts the pinned role. LOGIN/CREATEROLE flags alone leave authenticated connections alive; closure includes exact-session termination, no remaining sessions and observed original-password rejection.

History rights remain unchanged. Cleanup reads each object's actual owner and the old grantor, adds precisely the original three non-grantable privileges from those owners, removes the manager-origin copies under the pinned manager, restores trusted administration and revokes only the compiled manager union with RESTRICT. Final checks reject missing/extra privileges, changed role identity, arbitrary creator memberships, a retained password, different incarnation or changed grant origin. SQL completion is stored only after these checks. Unknown completion is resolved from the same immutable marker, never from expiry or absence.

## Composition and qualification boundary

Static public desired inputs can be owned by Helm. The mutable seed/root, generated credentials and effect receipts cannot. Distinct producer/schema/preparation/final-retirement processes receive only their purpose-specific private files. A future shared Restricted runner Job must not mount an as-yet-uncreated Secret: kubelet resolves volumes before its first init container. Generated projections can use finite memory-backed per-phase directories; original durable material remains in the protected seed.

The source adapters, canonical schemas and [fixed command/file-projection
compositor](initial-bootstrap-command.md) are implemented; native trusted
prelude-to-original-Pod qualification and the official Helm runner remain pending.
Static provider names use the same validation as the eventual provider profile:
five distinct, nonreserved names of at most 64 ASCII letters, digits, underscores
or hyphens. Reject invalid names before creating any bootstrap state or contacting
Kubernetes. No profile material identity is invented for this check.
Existing ADR-130 direct-command/schema binding remains mandatory. A completed
install must enter existing passive handover/history before opening DDL/manager/provider
credentials. An interrupted post-schema active preparation verifies original
bundle/head/table history and database incarnation without rerunning manager
readiness or grants.

Focused bootstrap unit/race tests and affected Go vet/fixture compilation pass. `TestInitialBootstrapManagerWithRealServices` also passes against actual PostgreSQL/OpenBao/S3: generated manager, embedded migrations, purpose/history roles, independently encrypted activation, history grant transfer and existing-session closure. Its seed/witness/read-authority ports remain explicitly synthetic; see the [terminal report](../../test/results/initial-bootstrap-manager-first-check.log).

The separate `TestInitialBootstrapGuardWithRealKubernetes` now passes actual policy compilation/enforcement and observation-only token checks, with [unchanged sources and complete cleanup](../../test/results/bootstrap-guard-native-after-check.log). Native testing reproduced two earlier invalid policy constructs: policy variables in match conditions, and the reserved `namespace` variable declaration. Matching now uses request fields directly; validation retains only the used `sub` variable. Exact protected resource names, administrator restrictions and observation exceptions are unchanged. This guard fixture creates no private seed or SQL/provider authority and does not qualify the complete bootstrap command sequence.

Final deletion of the Asservat-created SQL/provider source Secret copies is explicitly unfinished. The future transition needs completed handover, positive joined reader/writer and credential closure, exact original UID/resourceVersion, and a retained occupied-name tombstone that prevents recreation. No guard exception is added here. Clearing the seed alone cannot clean copied still-valid operator S3 credentials. Operator-owned original material and upstream credentials remain under their existing ownership.
