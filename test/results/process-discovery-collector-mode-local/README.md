# Native process component harness

The existing guarded collector harness now has an explicit `collector-processes` mode. It uses the existing chart/containerd opt-in, real node channel, two-container Restricted synthetic workload and one original five-second/2MiB request. It preserves exact request/result provenance, validates native JSON and privacy canaries, and records failure receipts or missing-upload stage before success assertions. Existing collector status/restart/Restricted-negative/uninstall checks remain active.

Root independently reviewed all six final files and the original VM guard, report defers, bounds and cleanup. Author self-audit is labelled separately. Four pure harness self-tests pass; focused race tests pass1.075s and tagged compilation passes. The actual external test skips locally: no workstation collection or kernel namespace operations were run. The mode has not yet been dispatched. Actual containerd/kernel qualification and the full installed SQL/grant/publication/MCP/React/native workflow remain pending.

Original handoff plus the one-file diagnostics delta define the final hashes; the earlier handoff remains unchanged. Compressed payloads reproduce the original bytes in `manifest.json`.

Final integrated pre-push exits0 (durable command record retained). The full bootstrap race package reports PASS116.108s, but its tool session and parent shell disappeared during steering; that original shell exit was not captured. The package output is retained with this limitation. No repeated full package run is claimed.
