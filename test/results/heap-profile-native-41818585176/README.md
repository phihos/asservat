# Installed heap MCP proof — native41818585176

Qualified source: `80593f9398ad9bf909afe9fd46a34752b3060ba1`.
Go exited 0 in 580.027s; job 918s. All 4,117 reported source hashes match
committed blobs; source stayed unchanged, cleanup was empty and scratch removed.

`provenance.json` maps every original/derived cache file to its deterministic
gzip archive, original byte length and SHA256. A path separator becomes `__`.
The original native `manual-heap.pb.gz` is wrapped once more for archival;
decompress its archive once to recover the exact 531-byte native file.
All 14 archived originals/derived files were decompressed and compared byte for
byte to the retained cache. The separate documentation-check log records local
contract validation only.

The original workflow/environment/logs and native bytes are distinct from
`verification.json`, `native-analysis.json` and local pprof output. The named
MCP workflow passed summary/native signed-total parity and fresh repeat preview.
It does not qualify installed heap React interaction, physical heap/RSS,
maximum-input worker containment, trace or S-05 completion. The successful logs
contain no detailed owner/demand phase markers.

Both retained CI/native event readbacks are `workflow_dispatch`. Manual CI is
code validation, not an eligible required PR check. Separately retained required
CI41821140504 passed with `pull_request` on the same head, including actual
`ci-ok`. PR160 merged normally as `5b765322106c8b76e5c73a87577548856b6d609c`.
`merge-readback.json` verifies that the complete merge tree equals the qualified
head. `deliveryEvidence` in the provenance maps the three additional gzip
readbacks; the original 14 native/derived archives remain byte-identical.
