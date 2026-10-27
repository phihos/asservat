package artifact

// Native artifact types (ADR-244). A type fixes the recorded native
// representation: manifest kind/evidence type, native media type and format,
// the server-generated filename extension and the coverage sentence shown with
// a download. It is not permission to acquire, publish or disclose anything.
// The empty name is the historical pod-status type, so existing expectations,
// their digests and manifests keep their serialized form.
const (
	PodStatusArtifact      = ""
	PCAPNGArtifact         = "pcapng"
	SyscallRecordsArtifact = "syscallRecords"
	HTTPHeadersArtifact    = "httpHeaders"
)

const (
	PCAPNGFormat         = "pcapng"
	SyscallRecordsFormat = "asservat-syscall-events/v1"
	HTTPHeadersFormat    = "http-response-headers/v1"
	// HTTPHeadersNativeLimit is the specified HTTP projection total (16 MiB).
	HTTPHeadersNativeLimit int64 = 16 << 20
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
	// DataClasses are the classes this increment can verify. Raw packet and
	// syscall-argument variants need their own reviewed increments.
	DataClasses []string
}

var nativeTypes = []NativeType{
	{Name: PodStatusArtifact, Kind: "kubernetesSnapshot", EvidenceType: "context", MediaType: "application/json", Format: ContextFormat, Extension: ".json", Coverage: "Selected pod-status fields only; no logs, messages or workload configuration.", MaxBytes: MaxContextBytes, DataClasses: []string{"metadata", "raw"}},
	{Name: PCAPNGArtifact, Kind: "packetCapture", EvidenceType: "packetCapture", MediaType: "application/x-pcapng", Format: PCAPNGFormat, Extension: ".pcapng", Coverage: "Packet headers of the selected pod, truncated after the transport header; no payload. Filtered, truncated or lost packets are not included.", MaxBytes: StreamingNativeLimit, DataClasses: []string{"metadata"}},
	{Name: SyscallRecordsArtifact, Kind: "syscallTrace", EvidenceType: "syscallTrace", MediaType: "application/x-ndjson", Format: SyscallRecordsFormat, Extension: ".jsonl", Coverage: "Syscall metadata of the selected pod as JSON Lines: names, results, timing and process identity; no arguments or buffers. Lost events are not included.", MaxBytes: StreamingNativeLimit, DataClasses: []string{"metadata"}},
	{Name: HTTPHeadersArtifact, Kind: "packetCapture", EvidenceType: "packetCapture", MediaType: "application/json", Format: HTTPHeadersFormat, Extension: ".json", Coverage: "Approved HTTP/1 response header fields as structured JSON, not a packet capture; no bodies, URLs or credentials.", MaxBytes: HTTPHeadersNativeLimit, DataClasses: []string{"metadata"}},
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
