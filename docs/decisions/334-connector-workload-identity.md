# ADR-334 — Workload cluster registration and compatibility

Accepted, 2026-11-14. Consolidates ADR-331 through ADR-334 before the first
release. The maintainer requires clusters to join and reconnect without a
copied Secret, a separate enrollment interface or lockstep image upgrades.

## Registration

An administrator adds each workload cluster's name and ServiceAccount issuer
to the hub's `clusters` Helm values. The hub derives its cluster ID from the
name. Registration survives restarts and failed connections. The installation
can add or remove clusters on upgrade. Removing a registration or marking it
revoked closes its connections and refuses its tokens. Registration needs no
bootstrap slot or per-process identity.

The workload release receives `hub.url` and, for a private CA, `hub.caBundle`.
Its connector presents a kubelet-rotated ServiceAccount token for that URL.
The hub verifies signature, issuer, audience, expiry and the configured
namespace/ServiceAccount subject. The hub can discover the issuer's public
keys and refresh on an unknown key ID. For an unreachable issuer, supply its
public JWKS in the hub values and update it on signing-key rotation. This is
the same trust arrangement as Vault's [Kubernetes JWT authentication](https://developer.hashicorp.com/vault/docs/auth/jwt/oidc-providers/kubernetes).

## Connection and local state

A connector uses one outbound HTTPS endpoint behind an HTTP/2 Ingress or
Gateway. TLS may terminate at the proxy. The hub sends installation and
cluster IDs, settings and the connector's own regional object-store
capabilities. The bundled store scopes each regional credential to its
cluster. The design allows optional client certificates with TLS passthrough
using a CSR authenticated by the same token. [Optional certificate design](../architecture/enrollment-activation.md).

The bundled SeaweedFS gateway limits each bucket policy to 20,480 bytes.
Putting every connector's statements in the evidence bucket reached 210,581
bytes for 65 registrations and stopped installation. Instead, each regional
write and history identity carries its own prefix-scoped policy in the existing
private IAM Secret. Adding a cluster changes that Secret without growing the
shared bucket policy. This uses the gateway's static configuration and requires
no IAM API service or additional credential. [SeaweedFS policy size](https://github.com/seaweedfs/seaweedfs/blob/4ab66fb76da83700739f5839e62fcaf15fb7d02a/weed/s3api/policy_engine/bucket_policy.go#L7-L11),
[static identity policies](https://github.com/seaweedfs/seaweedfs/blob/4ab66fb76da83700739f5839e62fcaf15fb7d02a/weed/pb/iam.proto#L170-L192).

The connector watches local namespace and workload metadata and delivers
changed capacity observations over its connection. The hub attributes each
observation to the authenticated cluster and wakes reconciliation on change.
The last delivered capacity state remains current during a disconnect.
On reconnect the connector compares digests and resends on mismatch.
[Cluster observations](../architecture/cluster-observations.md).

### Work dispatch

The former connector looked up owners every second and renewed two idle exchanges
per owner every 30 seconds. With 65 active connectors, that would mean 65 owner
lookups per second before any user started work. Protocol major 2 keeps one
outbound HTTP/2 work subscription per connector. A waiting owner sends a
PostgreSQL notification when it needs an exchange. The connector opens that
exchange through its existing connection. Federation resolves the requesting
owner's binding to a ready Pod address in the installed Service's EndpointSlice
and uses the configured native port. The connector verifies the TLS identity
of that exact owner process. Ordinary Service load balancing could select a
different replica with no waiting request.
An available exchange can serve further work within its original lifetime.

One database listener per federation replica receives work notifications. One
per hub-api replica hears subscriptions and reannounces its still-waiting
callers after reconnect. Neither notification persists a request, carries
credentials or grants collection authority. This uses the existing database
credentials and service endpoints. An idle fleet sends no owner lookups or
exchange renewals. Upgrade a development installation's hub and connectors
together when crossing from the old standby protocol to major 2. Registering before resynchronization
follows PostgreSQL’s documented startup ordering. [PostgreSQL LISTEN](https://www.postgresql.org/docs/18/sql-listen.html#SQL-LISTEN-NOTES).

## Compatibility

The hub checks the protocol major before handing out settings or storage credentials. The hub returns HTTP 426 with both values for a missing or incompatible major.
The connector also checks the major in a successful reply. Within a
major the hub sends only advertised operations and queries. A missing
capability refuses that request while other supported work remains available.
The Hello frame's byte limit bounds its capability announcement. A newer
release can introduce names without reserving slots in older releases.

Additional optional fields are ignored. Any field that changes the meaning
of a request needs its own advertised capability. A change that cannot be
ignored or refused per request requires a new protocol major. Image and
startup digests identify the executing build for provenance. The cluster
and hub can upgrade independently when they speak the same major and support
the required work. The release qualification target covers adjacent minors
in both directions. Each additional supported pairing costs a mixed-version
test. [Federation contract](../../specs/federation.md).

The context-start tests exercise HTTP/2 major negotiation and requests with
missing capabilities. The 2026-11-14 combined-mode Kind run used the same
binary in images with different digests and completed a pod-status capture
and download. Mixed-release installed qualification remains open.
