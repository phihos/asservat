# ADR-051 — Initial internal peer identity profile

Date: 2026-10-10. Status: selected for implementation under the maintainer's one-shot continuation; runtime qualification remains bounded by the tests actually recorded.

The signed-work verifier needs an independently authenticated peer, and TLS chain validity alone does not establish current cluster enrollment or node generation. Select TLS 1.3 client authentication with an installation-specific SPIFFE URI carrying immutable installation/cluster/peer/issuer-epoch identity. Node certificates additionally bind node UID, boot and collector epoch. Separate client/server certificate purpose, cap client certificates at one hour and consult current registration on every request, including reused TLS connections. The [peer identity contract](../architecture/peer-identity.md) defines exact encoding and bounds.

Reuse Go TLS/x509; no new mandatory identity service or PKI dependency is added. The profile does not require SPIRE or prescribe the operator's certificate key algorithm. Short lifetime limits disconnected credential exposure; current registry checks provide connected revocation and epoch rejection. Enrollment must verify node identity independently and issue only this fixed profile. Protect and rotate CA roots and work-signing keys separately.

Initial SQL state and its SELECT-only reader implement connector authentication. The [audited enrollment coordinator](../architecture/enrollment-activation.md) now adds bounded PKI signing and activation. Bootstrap issuance, node attestation and public listeners remain pending. Existing configuration/audit/capacity/privacy gates remain mandatory. This is an internal protocol refinement and does not change user authorization or introduce another user approval.
