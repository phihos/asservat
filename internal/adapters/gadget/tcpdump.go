package gadget

import (
	"errors"
	"time"
)

// ADR-248: the packet engine is Inspektor Gadget's published tcpdump gadget,
// pinned by digest and loaded from the collector image (no registry pull, no
// custom kernel program). scripts/fetch-gadget.sh fetches the same four blobs
// for the image build.
const (
	TcpdumpReference      = "ghcr.io/inspektor-gadget/gadget/tcpdump:v0.57.0"
	TcpdumpIndexDigest    = "sha256:2176a5bd659841ad7bdbed1633a52b744ccb4232f3fd567e2388361ddd8e047a"
	TcpdumpIndexBytes     = 2023
	TcpdumpManifestDigest = "sha256:38d9bd068b4ddd3276dce72ea87f57b2716eac64adcbe64a65edb45fa3906981" // linux/amd64
	TcpdumpManifestBytes  = 1416
	TcpdumpConfigDigest   = "sha256:6379a2273c831a836cdcd0fcf362dfe1c6d90a474944d24f1e909375b4a6e84c"
	TcpdumpConfigBytes    = 1354
	TcpdumpProgramDigest  = "sha256:1e492d7cf4ca1f91cc16ff4e74d3d06d70844780366d09612244c5a08f6ad5f2"
	TcpdumpProgramBytes   = 34224
	// TcpdumpBlobs is the image path of the blobs (blobs/sha256/<hex>).
	TcpdumpBlobs = "/usr/lib/asservat/gadgets/tcpdump"
)

var (
	// ErrEngineUnavailable: this build or node cannot run the gadget.
	ErrEngineUnavailable = errors.New("packet engine unavailable")
	// ErrTargetNotFound: no process of the pod runs on this node.
	ErrTargetNotFound = errors.New("capture target pod not found on this node")
	// ErrTargetHostNetwork: the pod shares the node's network namespace; its
	// traffic cannot be attributed to the pod (plan increment 17).
	ErrTargetHostNetwork = errors.New("capture target uses the host network")
)

// Frame is one packet as the gadget delivered it: at most the requested
// snapshot length of leading bytes, the original length on the wire and the
// kernel timestamp converted to wall time.
type Frame struct {
	Data []byte
	Wire uint32
	// TimestampUnknown marks legacy arrival fallback. False alone does not
	// qualify hub/node clock placement or continuous event-time coverage.
	// This bit fits the existing padding before At on supported 64-bit nodes.
	TimestampUnknown bool
	At               time.Time
}

// CaptureStats are the engine's own counters for one capture.
type CaptureStats struct {
	// LostSamples is what the gadget's perf reader reported lost.
	LostSamples uint64
}

// InputNotice identifies a gap in the engine input before the predicate runs.
// LostSamples is nonzero for a perf loss; zero means unknown input. It carries
// no provider error text. The caller must stop its meter and cancel capture,
// without waiting for capture to join inside this callback.
type InputNotice struct{ LostSamples uint64 }
