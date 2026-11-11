# ADR-324: Install the existing context workflow through Helm

Status: implementation candidate, 2026-11-11. The short actual Helm context
journey passes with separate hub/workload APIs and preloaded images. Same-API
qualification and a homelab trial remain pending. This does not mark the
specification complete.

The maintainer wants to install and try the working vertical slice now. Native
installed tests exercise actual product services, but their setup supplies
inputs that the advertised Helm path cannot currently produce. The chart omits
capacity, federation, promotion, baseline retention and processing operators.
The fixture also creates capacity objects and federation/key-service serving
Secrets. Public bootstrap normalization selects only its runner as an
administrator, leaving ordinary operator commands unable to administer the
guarded installation after enrollment. These are observed packaging defects.

## Decision

Complete one collector-free context trial using the existing runtime and
installer. Pass the supported public settings through the chart and decode the
rendered projection through the real typed consumer. Declare optional pool and
budget specs in the existing capacity input; the installer creates their exact
objects after its generated cluster identity is known. Exact marked replay is
allowed; conflicting or unmarked retained objects are refused.

Use the existing provider inbox for operator-supplied federation/key-service
serving certificate, key and CA bundles. The public recipe states the expected
hostnames. Validate both bundles before effects, then create the fixed Secrets
or reopen their exact contents. Do not generate a CA, change existing keys or
put private material in values or the public outbox.

Expose the existing explicit installation-administrator choice through public
bootstrap input. Omission preserves the runner-only contract. At most31 unique
Kubernetes User/Group actors may be selected, in addition to the derived runner,
within the existing32-actor guard bound. They use the existing administrator
branches for installation management and initial AccessBindings after actual
enrollment. This is broad installation trust and must be selected explicitly;
it supplies no browser identity, implicit evidence grant or new admission
exception. Original input remains immutable; this does not migrate completed
installation guards or enable later delegation-envelope revisions.

Provide `make image` for the existing static application and freshly compiled
console. It builds locally, includes no fixture helpers and neither pushes nor
deploys. A registry reference must use the actual published digest when an
operator separately chooses to distribute that image.

## Same-API independent probes

The fresh actual Helm same-API run at `9a55d5de` installs and enrolls but
cannot ready its workload: the hub and regional global namespace-label guards
mask each other's denial. A fresh owned Kind reproduction with two genuine
policies and unprivileged probe accounts fails in6.591s. Kubernetes returns
only the first policy's denial, so the second guard's exact proof is unavailable.
This affects every such co-installation, not a hypothetical permission change.

For the two global metadata guards, isolate only their no-effect probes:
namespace UPDATE is exempt from the other guards only when `request.dryRun`
is explicitly true and the object name differs from that guard's own pinned
probe namespace name. Workload CREATE has the same explicit dry-run condition
and must target a namespace other than that guard's own probe namespace.
Each guard still denies its own unprivileged probe. The exact policy/binding,
current identities, original proof interval and real object reads remain
mandatory. A missing or ineffective own guard must make the proof fail even
when another global guard remains installed.

All persistent CREATE/UPDATE protection and RBAC remain unchanged. Dry-run
responses supply neither persisted metadata nor evidence or execution authority.
This is a limited refinement of ADR-092's prohibition on broad dry-run
exceptions, confined to these two global metadata policies; private namespace,
source, credential and workload protection policies retain their existing
exceptions. No probe list, shared-guard owner, role, watch, process or additional
API request is introduced. Admission adds one constant-size CEL condition per
existing global guard, independent of workload/node count. The source contract
requires persistent metadata protection (REQ-CAP-004–006, REQ-PER-003/005), not
that an unrelated global guard mask an independent no-effect probe.

Existing pre-release guards with a different generated specification are not
adopted or silently rewritten. Fresh installation and exact-guard qualification
are required; this change makes no supported upgrade or rollback claim.

## Cost and verification

The observed defects block every operator attempting this Helm context path.
Reuse existing components:0 runtime processes, watches, roles or background
loops; no automatic collection or dependency installation. The capacity
producer uses4 GETs and at most2 CREATEs on first use; replay uses4 GETs.
Serving inputs add at most6 installer API calls for the two existing desired
Secrets. Explicit administrators add at most31 entries to existing guards.
There is no ongoing provider call or permission check added by these changes.

Verify malformed/foreign input refusal, exact replay and producer/consumer
parity locally. Then install the actual chart in a fresh owned environment,
using the product producers rather than fixture-created final inputs. Complete
browser/MCP context capture, publication and native download using explicit
operator-created permissions. Record actual exits, source hashes and cleanup.
Supported recovery, bundled dependencies, collectors, releases and the remaining
specification retain their separate unfinished scope.
