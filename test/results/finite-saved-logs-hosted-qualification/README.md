# Frozen saved-logs hosted qualification

Exact candidate `fb955e46fed5f44d76568a944d761c2980aa9ce1`. The manifest retains deterministic gzip originals and both hashes.

- [Resource workflow](https://github.com/phihos/asservat/actions/runs/42100969787): success; all4,825 source hashes match Git, unchanged sources, scratch removed, cleanup[]. Three near64MiB reader shapes under enforced256MiB/500m finish without OOM/swap: dense59,392,000B/12.119s; long96,182,272B/3.509s;128origins94,199,808B/3.328s. Synthetic encrypted reader/parser/TLS source only; no installed SQL/key-service or full-worker maximum qualification.
- [Installed workflow](https://github.com/phihos/asservat/actions/runs/42101047925): failure; Go/harness1,514.443s overall. The logs journey fails after32.10s waiting for the restarted synthetic HTTP listener, before logs acquisition. Its readiness poll requests4MiB/65,536 flushed records under100m CPU and a2s child deadline. All4,363 source hashes match Git, source unchanged, provider0, scratch removed and cleanup[]. This failure establishes no installed logs success.
- [CI](https://github.com/phihos/asservat/actions/runs/42100875392): failure; the preview descriptor is38,161B above the existing36KiB budget. The other CI jobs pass; the aggregate gate fails. No budget increase is authorized by this result.

The later corrections retain the original readiness deadline/resources, ask for one synthetic traffic record, reset joined connector ownership on reconnect while retaining terminal outcomes, and compact equivalent typed schema branches. New qualification must name its own source commit; these originals are not relabeled.

Local corrections pass the full contract race suite (12.128s), full bootstrap races (113.214s) and final `make pre-push` (including587 console tests/51 files). `fix-verification-manifest.json` binds the actual eight changed code/schema inputs to original logs and explicit exits. Baseline lifecycle/readiness/descriptor failures are retained. These are local checks; the next installed run remains required.
