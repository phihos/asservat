package gadget

// The syscall metadata engine is Inspektor Gadget's published traceloop
// gadget, pinned by digest and loaded from the collector image like tcpdump.
// Only the index, manifest, config and eBPF program are shipped: the gadget's
// wasm layer (which would install syscall argument definitions) is never
// fetched or linked, so the program emits syscall numbers, timestamps, the
// process ID and the return value, and never reads user memory. The engine
// refuses to run unless the argument definition map is empty.
const (
	TraceloopReference      = "ghcr.io/inspektor-gadget/gadget/traceloop:v0.57.0"
	TraceloopIndexDigest    = "sha256:e06e1c5f1397780162a91241771bd5833831dd6d7ec075e3bda6985404f97626"
	TraceloopIndexBytes     = 2158
	TraceloopManifestDigest = "sha256:7779c72c24ec9f1023ec837cc3caf7492396b2e5be29d71e06331d44c08bace6" // linux/amd64
	TraceloopManifestBytes  = 1666
	TraceloopConfigDigest   = "sha256:491c5f695113c3d2c5f5a4ea2897f631cffe8789c0434ac0df40f03189e54b74"
	TraceloopConfigBytes    = 1249
	TraceloopProgramDigest  = "sha256:49f885dd5bd0c6399efb1ead3971fa264558b5c3b81c2686486ab90f21841a73"
	TraceloopProgramBytes   = 67896
	// TraceloopBlobs is the image path of the blobs (blobs/sha256/<hex>).
	TraceloopBlobs = "/usr/lib/asservat/gadgets/traceloop"
)
