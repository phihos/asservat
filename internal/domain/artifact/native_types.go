package artifact

import (
	"strings"

	"asservat.local/asservat/internal/domain/identity"
)

// Native artifact types (ADR-244). A type fixes the recorded native
// representation: manifest kind/evidence type, native media type and format,
// the server-generated filename extension and the coverage sentence shown with
// a download. It is not permission to acquire, publish or disclose anything.
// The empty name is the historical pod-status type, so existing expectations,
// their digests and manifests keep their serialized form.
const (
	PodStatusArtifact = ""
	PCAPNGArtifact    = "pcapng"
	// RawPCAPNGArtifact keeps payload prefixes up to approved caps (ADR-279).
	RawPCAPNGArtifact      = "rawPcapng"
	SyscallRecordsArtifact = "syscallRecords"
	HTTPHeadersArtifact    = "httpHeaders"
	// PprofArtifact and GoTraceArtifact are a Go endpoint's native response
	// (ADR-284): gzip-compressed pprof protobuf and the Go execution trace.
	PprofArtifact   = "pprof"
	GoTraceArtifact = "goTrace"
)

const (
	PCAPNGFormat         = "pcapng"
	RawPCAPNGFormat      = "pcapng-raw"
	SyscallRecordsFormat = "asservat-syscall-events/v1"
	HTTPHeadersFormat    = "http-response-headers/v1"
	// HTTPHeadersNativeLimit is the specified HTTP projection total (16 MiB).
	HTTPHeadersNativeLimit int64 = 16 << 20
	// The profile formats are the names of specs/contracts/profile.schema.json.
	PprofFormat   = "pprof"
	GoTraceFormat = "go-trace"
	// ProfileMediaType is what net/http/pprof serves for both (debug=0).
	ProfileMediaType = "application/octet-stream"
	// The specified output maxima (specs/profiles.md REQ-PRF-002).
	MaxPprofBytes   int64 = 64 << 20
	MaxGoTraceBytes int64 = 128 << 20
)

type NativeType struct {
	Name         string
	Kind         string // manifest kind (action kind)
	EvidenceType string // privacy evidence type
	MediaType    string // native media type, inside the manifest and AAD binding
	Format       string
	Extension    string // server-generated filename suffix
	Coverage     string // fixed text; lifecycle coverage is appended per artifact
	MaxBytes     int64
	// DataClasses are the classes this increment can verify. Syscall-argument
	// variants need their own reviewed increment; the HTTP header projection
	// is an extract (ADR-282).
	DataClasses []string
}

var nativeTypes = []NativeType{
	{Name: PodStatusArtifact, Kind: "kubernetesSnapshot", EvidenceType: "context", MediaType: "application/json", Format: ContextFormat, Extension: ".json", Coverage: "Selected pod-status fields only; no logs, messages or workload configuration.", MaxBytes: MaxContextBytes, DataClasses: []string{"metadata", "raw"}},
	{Name: PCAPNGArtifact, Kind: "packetCapture", EvidenceType: "packetCapture", MediaType: "application/x-pcapng", Format: PCAPNGFormat, Extension: ".pcapng", Coverage: "Packet headers of the selected pod, truncated after the transport header; no payload. Filtered, truncated or lost packets are not included.", MaxBytes: StreamingNativeLimit, DataClasses: []string{"metadata"}},
	{Name: RawPCAPNGArtifact, Kind: "packetCapture", EvidenceType: "packetCapture", MediaType: "application/x-pcapng", Format: RawPCAPNGFormat, Extension: ".pcapng", Coverage: "Packets of the selected pod including payload, truncated at the approved per-transport byte caps; caps limit bytes and do not redact. Filtered or lost packets are not included.", MaxBytes: StreamingNativeLimit, DataClasses: []string{"raw"}},
	{Name: SyscallRecordsArtifact, Kind: "syscallTrace", EvidenceType: "syscallTrace", MediaType: "application/x-ndjson", Format: SyscallRecordsFormat, Extension: ".jsonl", Coverage: "Syscall metadata of the selected pod as JSON Lines: names, results, timing and process identity; no arguments or buffers. Lost events are not included.", MaxBytes: StreamingNativeLimit, DataClasses: []string{"metadata"}},
	{Name: PprofArtifact, Kind: "profile", EvidenceType: "profile", MediaType: ProfileMediaType, Format: PprofFormat, Extension: ".pb.gz", Coverage: "The Go endpoint's pprof response as served (gzip-compressed protobuf); sample labels and symbol names are the application's and are not filtered.", MaxBytes: MaxPprofBytes, DataClasses: []string{"raw"}},
	{Name: GoTraceArtifact, Kind: "profile", EvidenceType: "profile", MediaType: ProfileMediaType, Format: GoTraceFormat, Extension: ".trace", Coverage: "The Go endpoint's execution trace as served; it can contain goroutine, task and log text written by the application and is not filtered.", MaxBytes: MaxGoTraceBytes, DataClasses: []string{"raw"}},
	{Name: HTTPHeadersArtifact, Kind: "packetCapture", EvidenceType: "packetCapture", MediaType: "application/json", Format: HTTPHeadersFormat, Extension: ".json", Coverage: "Approved HTTP/1 response header fields as structured JSON, not a packet capture; no bodies, URLs or credentials.", MaxBytes: HTTPHeadersNativeLimit, DataClasses: []string{"extract"}},
}

// LookupNativeType returns a copy of the registered type, or false.
func LookupNativeType(name string) (NativeType, bool) {
	for _, t := range nativeTypes {
		if t.Name == name {
			t.DataClasses = append([]string(nil), t.DataClasses...)
			return t, true
		}
	}
	return NativeType{}, false
}

// NativeTypeForFormat maps a recorded native format back to its type.
func NativeTypeForFormat(format string) (NativeType, bool) {
	for _, t := range nativeTypes {
		if t.Format == format {
			return LookupNativeType(t.Name)
		}
	}
	return NativeType{}, false
}

func (t NativeType) AllowsClass(class string) bool {
	for _, c := range t.DataClasses {
		if c == class {
			return true
		}
	}
	return false
}

// Filename is server-generated from the opaque artifact UUID; no target name,
// label or user text enters it.
func (t NativeType) Filename(artifactID string) string { return "artifact-" + artifactID + t.Extension }

// RemoteNativeLimit is the largest native artifact the installed regional
// download exchange serves (ADR-248 interim, equal to the per-capture
// recording cap): one 8 MiB storage frame, so one response window is one
// 64 MiB accounting window, one remote conversation with one key binding and
// at most eight 1 MiB data frames. Larger recordings need the named streaming
// follow-up, not a raised constant.
const RemoteNativeLimit = FrameBytes

// DownloadLimit is the type's native size bound on the installed download path.
func (t NativeType) DownloadLimit() int64 { return min(t.MaxBytes, RemoteNativeLimit) }

// DownloadEvidenceType reports an evidence type the installed download path
// serves (ADR-248): pod-status context, packet captures (PCAPNG) and syscall
// metadata (JSON Lines, ADR-273), and raw Go endpoint profiles.
func DownloadEvidenceType(evidenceType string) bool {
	return evidenceType == "context" || evidenceType == "packetCapture" || evidenceType == "syscallTrace" || evidenceType == "profile"
}

// ValidNativeDownloadMetadata checks the fixed, type-derived facts of prepared
// native download metadata for artifactID: the type follows the recorded
// format, and the filename, size bound and a single-line coverage follow the
// type. Callers holding the expectation compare exact coverage and dates too.
// It is not authority to disclose anything.
func ValidNativeDownloadMetadata(artifactID string, m NativeDownloadMetadata) bool {
	t, ok := NativeTypeForFormat(m.Format)
	return ok && m.Filename == t.Filename(artifactID) && m.Size >= 1 && m.Size <= t.DownloadLimit() && m.SHA256 != (Digest{}) && identity.Text(m.Coverage, 1024) && !strings.ContainsAny(m.Coverage, "\r\n")
}
