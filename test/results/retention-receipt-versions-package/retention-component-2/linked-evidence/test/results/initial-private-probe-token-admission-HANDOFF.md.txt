# Frozen private probe TokenRequest correction

Three paths. The archived diagnostic native failure reached one TokenRequest HTTP422, zero reviews, original anchor and token claim persisted, no token response. The continuity policy matched the account token subresource but all allowed branches required the empty subresource. This patch adds only the explicit private-capability administrator request: exact target probe account/token/CREATE, configured singleton audience, exactly600seconds, v1 Secret fixed anchor name and UUID. The production claim, actual anchor/account UID checks, original deadlines and no-reissue behavior are unchanged. A failed/unknown original claim cannot be reset by this patch. No private-less policy bytes change.

The native fixture adds ten negative cases (account, audience, extra audience, shorter/longer duration, bound kind/name/UID, missing binding and nonadministrator). Administrator otherwise-valid mutations require this exact continuity denial; built-in too-short/UID validation and nonadministrator RBAC may reject earlier. A second fixture-owned empty anchor supports the wrong-name test; it is not product inventory. No credential or Secret contents enter logs.

Source research: https://raw.githubusercontent.com/kubernetes/kubernetes/master/pkg/registry/core/serviceaccount/storage/token.go confirms static TokenRequest validation and validating admission precede bound-object lookup, and the endpoint supplies default service-account metadata. It is source research, not a measured native verdict.

Checks: affected private adapter race suite plus integration compile exited0 (Kubernetes19.281s, integration1.051s). After final native negative-source refinement, original-policy golden + integration compile/race exited0 (see qualification-final.log). No external fixture run here; the native regression remains pending. Before regression evidence is the parent-owned archived diagnostic run, not a synthetic claimed pass.

Next: parent applies exact hashes and runs ^TestInitialPreparationPrivateProbeWithRealKubernetes$. Then continue the separate SQL composition stage. All payloads frozen.
