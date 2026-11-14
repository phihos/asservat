# Operator and user friction audit (2026-11-14)

The maintainer asked for every remaining "idiotic design decision" to be found
and shown without being asked. Five reviewers compared the specification, the
chart and the code with what operators of Argo CD, Grafana, Loki, cert-manager,
Velero, Kubeshark and OCM expect. Raw findings with file:line references,
comparable-tool behaviour, origin (maintainer decision or agent-added) and a fix
each are in [friction-2026-11-14/](friction-2026-11-14/). Already-known items
(join Secret, image-digest pinning, four connector endpoints; ADR-334) are
excluded.

| Area | Findings | High |
|---|---|---|
| Install, upgrade, operations ([ux-ops](friction-2026-11-14/ux-ops.md)) | 23 | 10 |
| Access, identity, administration ([ux-access](friction-2026-11-14/ux-access.md)) | 23 | 6 |
| Captures and policies ([ux-capture](friction-2026-11-14/ux-capture.md)) | 24 | 12 |
| Evidence, downloads, console, MCP ([ux-evidence](friction-2026-11-14/ux-evidence.md)) | 18 | 5 |
| Code and chart as shipped ([ux-code](friction-2026-11-14/ux-code.md)) | 36 | 14 |

## Nothing works with the defaults

- Capacity is empty, so every capture is refused; combined mode needs ~110–130
  lines of unmeasured byte/WAL/row arithmetic (OPS-03, U-05, UXC-14).
- No step-up flow is configured, so nothing can be approved (ACC-05, UXC-06).
- The node collector is off; bundled Keycloak needs a second install pass to
  copy group UUIDs, and the guide makes every user an installation
  administrator (OPS-02, ACC-01/02, U-07).
- A manual `initialize_processing` call is required (U-09); existing
  AccessBindings wedge the first permission acceptance until an undocumented
  ConfigMap exists (OPS-10, ACC-19, U-03).

## Ranked findings

1. **Only pod-status can be triggered** — "capture packets when my Deployment
   restarts" is refused (UXC-01).
2. **Values fixed at first install** — bundled Keycloak hostname/realm/redirects
   (upgrade fails, recovery wedges), capacity values silently ignored on
   upgrade, `federation.connector` counts (OPS-01, U-01, OPS-04).
3. **Connector stuck one hour after install** (U-02; fix in progress).
4. **UUIDs typed by hand everywhere** — clusters, namespace/workload UIDs,
   grant UUIDs, recipe SHA-256 digests in `recipeRef`, IdP group UUIDs copied
   into a custom attribute; the standard `groups` claim is ignored; bindings
   narrowed to a workload break when it is recreated (U-04, UXC-02/03, ACC-04,
   U-14).
5. **Second human approval with mandatory step-up** for raw downloads of
   evidence from an already reviewed policy, for a pprof GET, and within a
   5-minute submit window (EVD-01, UXC-06/07, ACC-06, EVD-03).
6. **Short human-facing deadlines** — download cut when the access token
   expires (5 min), 5 min / 4 requests per download at 1.2 MiB/s, preview
   expiry 2 min, approval 1 h, raw grants ≤ 8 h, live watch closes after 30 s
   without a read, survey results 15 min (EVD-02, U-12, U-11, OPS-12, EVD-10).
7. **Evidence and shares vanish quickly** — 72 h default retention (6 h for
   cores in the example), shares ≤ 7 days, weekly re-sharing (EVD-04).
8. **Policies expire** after 7–30 days or 100 runs; re-applying the same YAML
   is refused; lifetime byte budgets stop always-on recorders within hours;
   sensitive sessions stop after 1 h (UXC-11/12/13).
9. **Tiny hard limits** — 1 concurrent capture and 16 policies per cluster, 4
   capturing workloads per namespace in the example, 8 sessions installation
   wide in the trial profile, 15 joined clusters, namespace refresh silently
   skips clusters beyond 8, a 60 s post-trigger window that makes a 5-minute
   syscall recording impossible (UXC-14/15, U-05, OPS-05, U-08).
10. **No restore, backups stay in the cluster** — no recovery flag or runbook,
    pgBackRest to a local PVC, no SeaweedFS/OpenBao/realm backup (OPS-06/07).
11. **External services need dozens of hand-made objects** — OpenBao always
    required (static-key option missing), ~19 external OpenBao policies/roles
    and three PKI mounts, 9–13 S3 credentials with hand-written prefix
    permissions, ≥117 PostgreSQL connections, key names containing an ID that
    exists only after the first install (OPS-08/09, U-10).
12. **Mandatory CA bundles even for public CAs** (U-06).
13. **Downtime on every upgrade** — hub-api uses `Recreate`, hub-worker is a
    single replica (U-13).
14. **Five overlapping administrator concepts**; one person's access is
    written in 3–4 lists plus an AccessBinding; `processingOperators` required
    even without the privacy console (ACC-03, U-08).
15. **Team policies in the administrator-only namespace**; no cluster-wide
    binding for approver groups (UXC-02, ACC-07/08).
16. **Sharing needs recipient UUIDs**, no user search, a separate owner role
    (ACC-12).
17. **gdb workflow by hand** — core companions downloaded one by one, files
    named `artifact-<uuid>` (EVD).
18. **Broken examples and missing CRDs** — examples fail the spec's own
    validation; the chart ships no DebugCapture/EvidenceRecipe CRDs (UXC).
19. **Values schema accepts settings that crash-loop hub-api** (OPS-11).
20. **MCP**: 55 tools, capture tools off by default, a second OAuth resource
    for downloads (EVD).

## Maintainer decisions involved

Four findings trace to accepted decisions; each keeps the decision with less
friction:

- *One bounded independent approval for manual collection*: keep it for
  manual intrusive collection only; evidence from a reviewed policy and reads
  by someone who already holds the equivalent Kubernetes right (e.g.
  `pods/exec`) need no second person; step-up is optional, off by default.
- *Expiring policy grants for automatic intrusive actions*: keep expiry for
  intrusive automatic actions, with administrator-configured periods,
  renewal in place and idempotent re-apply; non-intrusive policies don't
  expire.
- *Administrator-enforced maximum retention*: keep the maximum; raise
  defaults (evidence 14 days, shares up to the retention maximum).
- *Storm protection*: keep rate and concurrency limits with usable defaults
  derived from cluster size, not lifetime byte budgets.

Everything else is agent-added and is removed or replaced.
