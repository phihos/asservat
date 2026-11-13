# Security evidence check (2026-11-13)

Maintainer rule: every security measure must be backed by external research;
measures nobody outside the project argues for are removed. Threat model:
ADR-328 (Asservat namespaces are administrator-only). Agent-authored ADRs are
not evidence. Each group was researched independently; verdicts rest only on
the cited sources and the threat model.

| # | Mechanism | Verdict | Keep | Remove |
|---|---|---|---|---|
| 1 | Five-second authority windows, re-checked per stage | REDUCE | One check per operation, reused ≤30 s (ADR-311); original hard deadlines; SQL effect checks at commit | Stacked 5 s windows and per-hop re-observation; 5 s stays only as an I/O timeout |
| 2 | One PostgreSQL login per purpose inside a process | REDUCE | One non-admin login per process, a separate migration owner, separate credentials per deployed process | In-process role splits, `session_user` OID pins, layout digests, per-purpose pools |
| 3 | Exactly-once and "uncertain counts as spent" | REDUCE | No blind replay of intrusive effects, via an idempotency key stored with the effect | Permanent charges, non-refilling signing attempts, paid re-preparation for GET downloads, namespace deletion to rerun bootstrap |
| 4 | Encrypted audit objects per call, prepaid audit obligations | REDUCE | One synchronous fail-closed audit record per security-relevant operation, append-only table, optional SIEM/Object Lock export | Per-event envelope encryption, intent/outcome pairs, prepaid audit accounts, deletion certificates, per-64 MiB records, audit before configuration use, Stop waiting on audit |
| 5 | Per-process PKI and enrollment between hub replicas | REDUCE | mTLS with one hub-only CA; a SQL owner row if routing is needed (or no forwarding at all) | Enrollment proofs, registration, certificate audits, signing budgets, activation, readiness PKI loop, streaming relay |
| 6 | Prepaid capacity reservations, never-released charges | REDUCE | Per-workload byte/object caps charged at admission, rate limits with burst, concurrency caps, retention by deletion | WAL/backup prepayment, prepaid renewals, charges released only after full inventory |
| 7 | Re-authorization on every read and hop | REDUCE | One authorization per public request (≤30 s reuse); Stop as urgent revocation | Hop and final-write re-checks, re-attestation per 64 MiB window, per-second peer re-resolution with stop-on-churn |
| 8 | Application encryption of low-sensitivity metadata | REDUCE | Evidence encryption (maintainer requirement); volume and pgBackRest repository encryption | Envelopes for capture-history settings and save reasons; plain rows under existing authorization |
| 9a | Collector boot-ID/epoch binding | REDUCE | Projected audience-bound Pod token + TokenReview + mTLS | Boot-ID equality, epoch/boot fields in sources and permits |
| 9b | Hub-signed JWS verified only by the hub | REMOVE | — | Internal policy-submission JWS |
| 9c | Encrypted audit of each ConfigMap revision | REMOVE | Log the accepted revision and digest | Encrypted pre-use configuration audit (Kubernetes audit covers it) |
| 9d | Share managers pinned to assignment UUIDs | REDUCE | Stable team identity; admin transfer only when the team is gone | Suspension on re-grant |
| 9e | Release image pinned in ~8 places | REDUCE | One image value per component, documented N−1 skew | Duplicate pins blocking independent upgrades |
| 9f | Reject group/world-writable mounted files | KEEP (keys only) | Check for private keys and credentials | Check for non-secret configuration |
| 9g | 1 h client certificates, registry check per request | REDUCE | 1 h certificates; registry check at handshake/renewal or ≤30 s reuse | Per-request registry lookups on reused connections |

## Key sources

1. Kubernetes webhook authorization cache (5 min allow / 30 s deny):
   https://kubernetes.io/docs/reference/access-authn-authz/authorization ;
   SpiceDB consistency: https://authzed.com/docs/reference/api-consistency ;
   RFC 9700 token lifetimes: https://www.rfc-editor.org/rfc/rfc9700
2. OWASP SQL Injection Prevention:
   https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html ;
   GitLab, Harbor, Sentry, Grafana single DB user (see group report);
   CIS PostgreSQL owner/user split
3. IETF Idempotency-Key:
   https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header ;
   AWS idempotent APIs: https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-apis/ ;
   Kubernetes Jobs are at-least-once: https://kubernetes.io/docs/concepts/workloads/controllers/job/
4. Vault audit (fail closed, HMAC): https://developer.hashicorp.com/vault/docs/audit ;
   Kubernetes audit: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/ ;
   NIST SP 800-53 AU-5/AU-9; OWASP Logging Cheat Sheet
5. Vault HA shared cluster certificate: https://developer.hashicorp.com/vault/docs/concepts/ha ;
   etcd peer TLS: https://etcd.io/docs/v3.5/op-guide/security/ ;
   Teleport proxy peering: https://goteleport.com/docs/zero-trust-access/management/proxy-peering/
6. OpenStack Nova counted quotas (dropped reservations):
   https://specs.openstack.org/openstack/nova-specs/specs/pike/implemented/cells-quota-api-db.html ;
   Loki limits: https://grafana.com/docs/loki/latest/configure/loki-limits/ ;
   OWASP API4:2023
7. OWASP Authorization Cheat Sheet (per request):
   https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html ;
   Cilium identity convergence: https://docs.cilium.io/en/stable/security/policy/lifecycle/
8. Grafana database encryption (secrets only):
   https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-database-encryption/ ;
   NIST SP 800-111; pgBackRest repository encryption
9. KEP-4193 bound tokens: https://www.kubernetes.dev/resources/keps/4193/ ;
   Kubernetes version skew: https://kubernetes.io/releases/version-skew-policy/ ;
   SPIRE default SVID TTL: https://spiffe.io/docs/latest/deploying/spire_server/

## Order of removal

Most of these disappear with the Helm-native installation and the guard
removal (groups 5, 9a–9c, 9e). The rest are separate runtime slices, ordered
by cost to users: 1 and 7 (availability failures), 3 (dead ends), 6 and 4
(storage and KMS load), 2 (connection budget), 8, 9d, 9f, 9g.
