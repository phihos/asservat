# Initial audit version enforcement checkpoint

33 payloads; no live integration yet. Every active recognized installer format
uses the version-required audit adapter. Fresh bootstrap v4 binds preparation
services v2 and installer v2 before effects. Existing root/input bytes remain
unchanged; unknown history, changed service intent and missing/null audit versions
deny without fallback or authority. The original full bootstrap fixtures enable
backend versioning before product execution and require a pinned initial receipt.

Checkpoint v3: five-package compilation and four intended packages passed broad
initial regressions: 152 top-level / 703 named PASS, one explicitly native-only
skip (TestInitialRuntimeObjectRoundTripWithRealKubernetes), 341.124 seconds including
race build/package execution. The corrected candidate passed vet. Architecture
stopped because its disposable mirror used symlinks for go:embed data; no product
failure or completed architecture qualification followed. All 3001 dependencies
and 32 payloads stayed exact. The old version-optional control reproduced two
missing-version receipt failures. This former draft retained a weaker legacy
constructor and is superseded by v4.

Checkpoint v4 differs at exactly three paths: installer audit constructor, its
actual TLS regression, and the native initial-installation fixture enabling
versioning. Other v3 Go payloads remain byte-identical. Compile8.143s, controlled
version-optional before2.884s (expected exit1, all four intended missing/null
failures across both accepted formats), corrected races5.738s (4 top/30 named,
zero skips), vet1.282s, Go architecture0.981s and canonical spec4.987s all pass.
All 3001 dependencies/33 bases/payloads stay exact; owned tmpfs build mirror is
removed. The actual native bootstrap/initial-installer run is still required.

The pre-reboot handle45687 has no retained terminal result; temporary output was
lost and is unqualified. Checkpointv2 stopped before any Go job because an
unrelated core.4751 existed outside the frozen source set. Only its metadata was
inspected; no contents were read or removed. V3/v4 exclude that exact non-source
file. Its timestamp predates the reboot; the v3 note saying it appeared after
reboot means discovery time and does not establish creation time.

This closes adapter/format enforcement, not all physical-version accounting,
provider IAM, deletion, recovery, runtime refresh/startup or a public workflow.
No chart/runtime enablement is included.

Manifest SHA256: b9654aa55acd161e91ce5779fed0633d5fc07c000b790ebc668a431a272c7ce2
Result SHA256: 1357cd64bbed2557b393925f8cd181c058900dedf84f3d8195a73e26a6b43212
Runner SHA256: d31f6080c436d984b41cf622c09762d9a83091d20e54cd579c4c022e21cdc54c
