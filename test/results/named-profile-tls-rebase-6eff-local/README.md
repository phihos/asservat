# Private named-endpoint TLS rebase: local proof

Source `008be29ee5d31e1b86f1a72bba5636c99cd30f60` preserves the seven TLS patches above `6effd250a4d8c114d6815da1a422dfee3bbec716`. All seven stable patch IDs and signatures, and all 33 TLS-modified internal Go files, were verified; no conflicts or manual source edits occurred.

The three Python selector suites passed (35 + 3 + 2 tests). The corrected four-package race and explicit-file synthetic application race passed. The first aggregate invocation failed because the synthetic application directory uses `go:build ignore`; its complete setup-failure log and exact command remain archived alongside the successful corrected invocations. No source change was needed.

`verification.json` records exact commands, working directory, environment overrides, actual exits, source identity and the SHA-256/size of every original and compressed file. Nine original cache files are retained byte-for-byte as deterministic gzip archives; all complete decompressed files were compared with their originals. The archived handoff/provenance/signature records retain the detailed source and review results.

This is local preparation evidence. Installed TLS remains unqualified; no hosted run, native collector, full pre-push gate, push or publication occurred. PR162 merge/readback remains a separate prerequisite for publishing the TLS candidate. No auth implementation is included.
