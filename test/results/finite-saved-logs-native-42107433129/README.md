# Saved-logs installed preview failure and green CI

Frozen signed candidate `67a28e07c87295da2aab354f24d7595993cb28ac`.

[CI42107404692](https://github.com/phihos/asservat/actions/runs/42107404692) completes successfully: all15 jobs including the aggregate gate pass. The independent eight-file review is clear, with all reviewed input hashes independently verified against Git.

[Installed42107433129](https://github.com/phihos/asservat/actions/runs/42107433129) fails (Go/harness1,486.522s). The original Pod restart and one-record listener readiness succeed. The logs journey fails at its first preview after4.78s withHTTP503, before collection. Product diagnostics show target/compile/processing/draft storage completed; a new local actual-compiler/C20 regression reproduces the shared output schema rejecting `/data/lifecycle_plan/actions/0/requestedBefore:const` for a finite logs lookback of1h. There is no installed logs success.

All4,363 input hashes match the original Git commit; sourceUnchangedDuringTest=true, providerLogExit0, scratch removed and cleanupFailures[]. Original reports/logs and independent audits are retained as deterministic gzip with both hashes in the manifest. The enclosing ZIP SHA256 is `aec443967c209e993d498136706a1ac8d0d795baf16e952a6f36cb5af93c1ab1` (245,566B); the original ZIP remains in the local cache.

A separate max-shape regression exposes the older8MiB public preview cap being applied to a64MiB logs plan. The subsequent correction uses the qualified finite-log ceiling and a dedicated log-window lifecycle shape; packet/syscall onTrigger prehistory remains forbidden. New qualification must name its own commit. No original result is relabeled.

Local correction evidence is retained in `local-fix-verification.json`: full affected races0 (presentation419.743s/contracts12.415s/manifest2.967s), final pre-push0 including587 console tests/51files, and clear independent review with ten current source hashes verified. Original schema and numeric-ceiling failures and the initial golden-example gate failure remain separate. This does not qualify an installed logs journey.
