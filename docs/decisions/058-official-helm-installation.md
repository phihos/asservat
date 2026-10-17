# ADR-058 — Official Helm installation

Date: 2026-10-10. Status: accepted by the maintainer. Helm is the officially supported installation method; this confirms and makes concrete the earlier packaging proposal.

Follow-up: [ADR-063](063-small-deployment-alternatives.md) permits explicitly selected bundled data services and internal identity/key providers. The original prohibition below concerns implicit installation; it does not prohibit the requested small profile. Runtime qualification remains pending.

Maintain one first-party `asservat` chart with `hub`, `cluster` and evaluation `combined` modes. Package canonical generated structural CRDs in `crds/`. Publish the chart through OCI when release publication is authorized, and support installation from a verified local archive for disconnected operators. Do not install PostgreSQL, object storage, KMS, Keycloak or a broker as implicit dependencies. Keycloak is the maintainer-selected first identity provider; configuration is explicit and credentials remain in existing Secrets.

CRD schema migration is an explicit administrator step before dependent code upgrades. Do not use hooks that delete/recreate CRDs, automatically force ownership conflicts, silently reverse SQL migrations or erase evidence during uninstall. Control, collector and analysis authority remain separate as defined in [applications](../architecture/applications.md). Existing collection/privacy gates determine runtime availability independently of Helm success.

The first development chart installs configuration foundations only because runnable role entry points and their complete authority/custody/privacy integration are unfinished. It must report this in its name/metadata documentation and install notes and reject runtime enablement. Add each role's deployment templates and tests alongside that role's implementation, without placeholder images or unqualified broad permissions. The [installation guide](../installation/helm.md) records the current package, planned runtime contract and actual verification scope.

Use the maintained Helm CLI and existing Python test environment; no new Helm plugins or packaging framework. Static tests cover all modes, schema rejection and packaged resources. An owned Kubernetes fixture tests install/upgrade/rollback/uninstall, structural validation and retained CRD/custom-resource identities. These tests establish package lifecycle behavior, not a production debugging platform.
