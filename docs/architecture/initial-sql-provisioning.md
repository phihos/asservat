# Original initial SQL provisioning

This continues ADR-123 through the actual private `initial-prepare` command. It
uses the existing ADR-100 SQL role provisioner and ADR-120 original credential
binder; it does not activate the installation or approve database recovery.

An explicit `sqlMaterial` reference selects the immutable, installation/request
bound bootstrap material. The material Secret is supplied by the protected
bootstrap and pinned by UID; the producer does not generate another password or
adopt a replacement. The first credential binding retains this reference, the
full startup digest containing the actual gated Pod UID, and the original
fifteen-minute interval. Subsequent calls cannot select another material source
or extend the interval. This selection remains independent of PostgreSQL role
creation and never claims that external administrator credentials were issued by
Asservat.

Before a preparation mutation, the command validates all local public provider
settings, independently reads the exact immutable material UID and validates its
three distinct unissued password values, and loads the fixed `sql-maintenance.json` credential with the existing protected
mount and TLS connection builder. A bounded read-only provider check
requires the supported non-superuser CREATEROLE profile. These maintenance
credentials remain in the bootstrap process and never enter the activation Pod.

The command reads the nine acknowledged public inputs and current original gated
Pod. It returns a defensive copy of those public values with the original short
observation deadline. Pending public CREATE operations cannot be completed by
this read path. The existing original probe supplies the independent target
namespace enforcement check; it never inherits the administrator bearer wrapper.
Every actual credential effect reacquires its own current guard and retains that
original deadline through blocking work.

The private state has one additional closed SQL intent and optional target Secret
receipt. Only an acknowledged first CAS permits the existing Secret producer's
one CREATE. An uncertain intent response grants no CREATE; when the intent is
present, retries perform exact-content GET only. A missing target remains
unresolved. The known target UID is immutable. The SQL payload must match the
original material, startup digest and credential dates before the claim, and an
expired original interval cannot admit a new credential Secret effect. The
private document contains no target payload hash. The target Secret is immutable
and uses the fixed `<credentials>-sql` key; it is separate from the future final
provider projection. This adds one bounded target object and one private receipt,
not another public create journal entry.

The actual PostgreSQL provisioner receives the retained original credentials under
the original current Kubernetes lease. Its existing transaction and role checks
preserve all-or-none preparation/audit/activation role identity, exact passwords,
finite validity, pristine requirements and retained-role retirement semantics.
An unknown or late COMMIT is not reported as successful setup. Retrying uses the
same role names and material and never treats absence as permission to recreate
an activated installation. Final current checks do not renew the earlier lease.

This checkpoint does not create OpenBao or S3 credentials, assemble the activation
Pod's final provider Secret, remove staging protection, ungate the Pod, observe
activation, or retire issued credentials. Those producer steps remain required.
The original probe and SQL credential expirations also remain binding; recovery
across a completed, failed or expired activation attempt must preserve its actual
historical disposition and cannot mint a fresh witness by resetting setup.

Focused race tests cover prepared-input UID replacement and post-read expiry,
independent returned slices, pre-effect immutable material checks, concurrent SQL
Secret claims, lost claim/create/receipt replies, and original expiry after the
Secret response. The wider Initial* Kubernetes/bootstrap/contract selection and
integration-source compilation also pass, including the retained legacy policy
golden checks. Schema checks use the repository validation environment with
format checking. Actual commands and measured times accompany the frozen handoff.

`TestInitialPreparationSQLWithRealKubernetesPostgres` composes the native preparer,
probe, original material binder, target Secret and scoped SQL role manager, tests
unchanged role verifiers/deadlines on replay, and checks that retired roles cannot
be revived. Its trusted fixture supplies private/material roots and maintenance
grants; public unused provider endpoints are explicitly synthetic. The Pod stays
gated and no activation is expected. Its own fresh owned context fixture now
passes all 20 named entries, with unchanged source hashes and complete cleanup;
see [implementation progress](../implementation-progress.md) for the actual
report. It does not run the installed command or qualify provider handover.
