# ADR-059 — Separate human SSO from recurring policy authority

Date: 2026-10-10. Status: **accepted by the maintainer**. This record supersedes the research recommendation of a mandatory Keycloak directory reader and refines recurring execution under REQ-PER-007. It does not reinterpret existing human-bound grants. The maintainer accepted the recommendation after reviewing the provider-neutral alternatives.

## Context

The current design lets policy approvals last days while human group assertions last at most five minutes. Login-only synchronization cannot provide continuously fresh identity for an absent human. Directory polling and personal offline refresh are not the only choices: an unattended policy can have independently delegated workload authority. Primary-source findings and qualification limits are in [background identity research](../research/background-identity.md).

## Accepted decision

Use standard OIDC sign-in and bounded session refresh for human console/MCP access. Do not require a Keycloak directory-reader account or retain personal offline credentials for ordinary recurring policies. Keep current human assertion freshness, source/deny checks and evidence-disclosure rules.

Make recurring team policies explicitly delegated automation: administrator-configured Kubernetes permission resources establish a bounded team/workload envelope, current maintainers author policies within their own rights and that envelope, and the existing review covers the exact executor/scope and applicable intrusive actions. Workers authenticate independently; a protected accepted delegation supplies policy-specific execution authority. An internal worker's general privileges, old human group snapshot or approver role alone never supplies that authority. Do not require developers to create IdP accounts or secrets.

The creator remains an immutable audit actor. Their logout or departure does not revoke independent team-policy authority. Their future management, watch, read and download operations still require current personal rights. Removing the policy/delegation or its current owner/workload assignment, explicit deny, expiry or exceeded budgets prevents new work/renewal under existing freshness and cancellation bounds. External IdP changes are only known through fresh assertions or a separately qualified lifecycle integration; do not promise immediate offboarding with login synchronization alone.

Optional user-bound unattended execution would require explicit current-user authority, such as standard offline delegation, and stop when that authority cannot be refreshed. Defer this mode and optional SCIM/security-event integration rather than making them installation prerequisites. Ordinary browser refresh is not the same feature as a personal offline credential retained to execute jobs after logout.

## Impact and adoption gate

This changes REQ-PER-007's default executor for human-authored recurring policies. It needs aligned permission/digest/grant contracts, owner/audience handling, saved-recording rules, UI/MCP explanation and tests listed in the research. No automatic migration, stale-claim extension, personal result-access transfer or controller-privilege fallback is allowed. The normative refinement is [team policy automation](../../specs/policy-automation.md). Configuration, eligibility and initial SQL/encrypted acceptance components implement part of it; protected source/signature/compiler production, atomic runtime composition and public policy activation remain qualification gates. This document is not execution authority.

Independently authorized team policies continue when their creator leaves. Their management, live watching and evidence access remain subject to current personal rights. This is the accepted default; user-bound offline execution and external lifecycle integrations remain deferred optional modes.
