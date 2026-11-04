# First installed heavy-profile run: terminal failure

Run [41830591107](https://github.com/phihos/asservat/actions/runs/41830591107)
used exact source `87df6794064de4423d92745d826aab735dd36b78`. Go exited **1**
after **528.356 seconds**; the harness and workflow also failed. Artifact upload
completed successfully. This was not a job timeout or upload failure.

The first approved capture, encrypted publication and authenticated native
download reached the local-tool assertion. `go tool pprof` exited successfully,
but selected `counter-15` and dropped all 100,000 functions under its default
cutoff (`cum <= 7500`). The fixture then failed because stdout contained no
`synthetic.` function name. The first fatal is in `context-storage.log` lines
96–102. Line 97 contains a 1,346,323-byte synthetic padded comment; avoid printing
it while inspecting the short surrounding excerpt.

The downloaded native file is retained once, byte-for-byte:

- Filename: `manual-profile-12e6017b-c54c-402c-ad21-246590931790.pb.gz`.
- Size: **9,394,862 bytes**.
- SHA-256: `853f5ed2f0a6afa8c64dcef9d0715e49b9435966406cde3b108f599a63084a9d`.

It matches the prepared ten-second baseline input exactly. These were prebuilt
synthetic profile bytes served through the approved acquisition path, not a
measurement of sampled application CPU or collector overhead. The second
capture, both comparisons, comparison SQL/key-join checks and all worker/cgroup
probes were **not reached**. This run qualifies no worker resource result.

The private terminal staging directory preserved only the separate generator's
log and manifest, as expected before observers were called. That producer
recorded exit 0, 463,672 KiB peak RSS and 3.622550 seconds outside the worker
cgroup. These are observations from this run, not universal memory limits.

All **4,123** submitted source hashes independently match `git show` blobs from
the exact run commit. The environment report records unchanged sources,
`cleanupFailures=[]` and build scratch removal. The workflow's later Kind
read-back states `No kind clusters found.`

`archive-manifest.json` indexes every original file and derived verification,
including stored and original SHA-256 values. Original workflow metadata,
artifact metadata, full workflow/Go/timing/provider logs and the prepared input
manifest are retained. Text/JSON files use deterministic gzip (mtime 0, empty
filename); the already compressed native file was copied without recompression.
The artifact ZIP and duplicate copies of the native are excluded. Every stored
payload was read back against its cache original. No rerun, source fix or
qualification claim is part of this archive.
