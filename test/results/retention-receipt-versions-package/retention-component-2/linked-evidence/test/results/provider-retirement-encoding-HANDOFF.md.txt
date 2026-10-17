# Exact provider invalid-accessor serialization

Five frozen paths, all existing bases match current live. No live source edits or external lab by this agent.

The real provider diagnostic already established synchronous revoke204 followed by accessor lookup400 with one error that differs from the bare string; it failed before checking the original token. Pinned server source establishes the exact encoding: request_handling.go appends routeErr to go-multierror; sdk/logical/response_util.go serializes err.Error() as one JSON errors element. The pinned formatter emits exactly the single-error wrapper tested here. Sources:
- https://raw.githubusercontent.com/openbao/openbao/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/request_handling.go
- https://raw.githubusercontent.com/openbao/openbao/a5db72cef75c24b920ade02065b18dd8eb666bac/sdk/logical/response_util.go
- https://raw.githubusercontent.com/openbao/openbao/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/token_store.go

The correction recognizes only the existing exact plain invalid-accessor message or its exact pinned single-multierror encoding, only for the existing POST lookup-accessor HTTP400 proof. It additionally rejects the SDK RawError fallback. Original token HTTP403 remains independently required. No substring/whitespace normalization, arbitrary400 acceptance, polling, retry, new grant or deadline change.

Unit regression before fix: TestInitialProviderPinnedRetirementEncoding exited1 with pinned single-error retirement rejected. After: all TestInitialProvider races exit0. Negative cases cover raw/plain body, multiple/wrapped-multiple errors, prefix/suffix/whitespace, missing-accessor400, wrong status, and original-token200/400/401/404/503. Positive wrapped retirement/replay performs one original issuance only. Vet KMS/integration exit0. Commands use TMPDIR external,GOMAXPROCS2,-p2,overlay.json; logs are preserved.

The existing actual fixture now reports exact_wrapped_invalid_accessor only as a boolean and records successful retirement traces, preserving64-entry cap/no body logging. Parent next runs the same TestInitialProviderIssuerWithRealOpenBao, then full TestInitialPreparationProvidersWithRealServices if it passes. No after-fix native success is claimed yet. ADR129 remains source-only during that lab.
