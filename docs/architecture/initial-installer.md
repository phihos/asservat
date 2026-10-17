# Protected initial-installer executable

[ADR-099](../decisions/099-protected-initial-installer.md) connects A-INSTALL's
bootstrap composition to the [initial-activation coordinator](initial-installation.md).
This is a private finite maintenance process, not a developer-facing command or
an independent approval flow. C-04/C-08 retain the activation/audit contracts;
C-21 supplies native workload protection and inert object generation; C-20 owns
the closed [startup wire contract](../../specs/contracts/initial-installer.schema.json).

`asservat initial-install` accepts no additional arguments. It reads
`/run/asservat/initial-installer/deployment.json` through the shared confined,
bounded regular-file loader. It suppresses process core dumps before reading
credentials. Provider connections require explicitly configured trusted HTTPS
or PostgreSQL TLS. Ambient credentials, insecure fallback, redirect and proxy
selection are unavailable. Separate fixed files provide `sql-prepare.json`,
`sql-audit.json`, `sql-activate.json`, `audit-storage.json`, `audit-wrap.token`,
`audit-unwrap.token`, `kube-writer.token` and `kube-probe.token`.

`BuildInitialInstallerWorkload` returns a gated Restricted Pod, writer/probe
accounts, exact named namespace roles and read-only guard/namespace discovery.
It performs no Kubernetes writes. The Pod cannot restart automatically or
create another Pod. Its image is digest-pinned, root filesystem is read-only,
all capabilities are dropped and there are no host mounts. Ordinary evidence
collectors and applications are outside this dedicated namespace.

Provisioning order is significant:

1. Establish a clean dedicated namespace and scoped accounts; create the inert
   Pod with no credentials and retain its UID/defaulted-spec digest.
2. Install the exact namespace and source/witness guards. Retain their UIDs,
   generation and binding resource versions, plus actual source/witness UIDs.
3. Create the closed immutable public inputs. Qualify a separately authenticated
   namespace-guard denial before creating provider credentials.
4. Provision finite audit/provider roles and the revocable probe credential in
   protected Secrets; remove only the same Pod's scheduling gate.
5. The executable verifies live Pod/account/guard identity before opening SQL,
   composes separate preparation/audit/activation stores and executes ADR-098.
6. Independently inspect its exact SQL result; retire installation credentials
   and normally remove the terminal Pod. Pod success alone is not proof of the
   full platform, nor authority to start the restore protocol.

The writer is authenticated online using the actual projected token. Protection
checks the exact current namespace policy twice around its independent probe,
the live account UIDs/deletion state, Pod UID/specification and namespace UID/deletion state. Only node assignment
and removal of the initial scheduling gate are excluded from the spec digest.
The witness wrapper preserves the earliest original protection/witness deadline,
which remains binding in the SQL transactions. Neither static constructor inputs
nor a test-created account supply recovery authority.

The installer holds all its purpose credentials in one trusted finite process;
separate SQL roles limit accidental cross-facet effects, not process compromise.
Their [provisioning and retirement](initial-sql-credentials.md) uses random
installation-specific logins and retained private state; the maintenance principal
is never mounted here.
It never holds raw-evidence unwrap authority. Provisioning must revoke SQL/key/store
credentials after success or abandonment; deleting a Secret alone does not revoke
external provider credentials or immediately invalidate cached Kubernetes token
authentication. Confirm retirement and retain uncertainty until then. A consumed/expired attempt never silently starts
again with new pins, a new Pod or a new plan.

Actual qualification is recorded in [implementation progress](../implementation-progress.md).
The native fixture provisions synthetic provider credentials and protected objects
before running the actual executable. It does not establish a complete production
provisioner, credential-retirement supervisor, static-key bootstrap, restored-state
reconciliation or a working chart installation.

## Required immutable audit versions

[ADR-151](../decisions/151-initial-audit-version-requirement.md) requires the
versioned audit adapter for both recognized installer v1 and v2 inputs. Fresh
bootstrap v4 produces services v2 and installer v2 with that exact choice bound
into the original immutable service intent and installer plan. Loading an older
input preserves its bytes and never permits an unversioned audit effect. Missing
or null versions deny after an uncertain write; no fallback, retry or latest-key
adoption grants activation. Component TLS/downgrade tests pass; native qualification
and complete physical-version retirement are tracked in [implementation progress](../implementation-progress.md).
