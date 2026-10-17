# Deterministic private fixture role names

Two test files only. `custodyID` keeps a stable UUID prefix and advances the final counter. The fixture used the first twelve hex digits, so every independent scenario attempted to create the same PostgreSQL roles. Preserve the complete UUID; the longest resulting role is 51 bytes, below PostgreSQL's 63-byte limit.

Actual before evidence: `test/results/connector49-overlap-after.log` failed both exhausted-source subcases with SQLSTATE 42710. The same run reached actual client/server activation, backing continuation, original process-date preservation and the private-view checks; it remains a failed suite.

The new deterministic regression exercises two IDs sharing the original truncated prefix and all seven SQL duties. `before-overlay.json` reproduces the original helper expression; `overlay.json` supplies the fixed fixture. Before regression exited 1 and fixed race/compile exited 0 (`evidence/before.log`, `evidence/after-race.log`); integration-package vet exited 0 (`evidence/vet.log`). Both source payload hashes remained unchanged. No external fixture ran. Parent must rerun the exact connector native fixture; its result remains pending.

No product SQL, role privileges, sources, deadlines or denial assertions change. No live file was edited.

Manifest SHA256: `cd65baeb033a9db02fc4ebf1d8973e330183564cb8a6c60335319c002a6a0f19`.
Patch SHA256: `04b4a2d51eee4d0ee4cc7f690e4819c154d06fb6c13dc21ea10a6fe97debe08c`.
