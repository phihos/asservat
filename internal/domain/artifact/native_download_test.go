package artifact

import (
	"fmt"
	"testing"

	"asservat.local/asservat/internal/domain/identity"
)

// ADR-248: prepared download metadata follows the recorded format's type;
// pod status keeps its historical facts and 4 KiB bound, and every other type
// is bounded by one 8 MiB frame on the installed download path.
func TestPreparedDownloadMetadataFollowsType(t *testing.T) {
	id := "10000000-0000-4000-8000-000000000002"
	p := PreparedDownload{Preparation: DownloadPreparation{SessionID: id, BatchID: id, Generation: 1}, Scope: DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "wl", PodUID: "pod", Version: Digest{7}, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}}}
	etag := fmt.Sprintf(`"v1-%x"`, p.Scope.Version)
	for _, c := range []struct {
		name   string
		m      NativeDownloadMetadata
		accept bool
	}{
		{"pod status", NativeDownloadMetadata{Filename: "artifact-" + id + ".json", Format: ContextFormat, Coverage: "Selected pod-status fields only; no logs, messages or workload configuration.", Size: MaxContextBytes}, true},
		{"pod status over 4 KiB", NativeDownloadMetadata{Filename: "artifact-" + id + ".json", Format: ContextFormat, Coverage: "c", Size: MaxContextBytes + 1}, false},
		{"pcapng 8 MiB", NativeDownloadMetadata{Filename: "artifact-" + id + ".pcapng", Format: PCAPNGFormat, Coverage: "c", Size: RemoteNativeLimit}, true},
		{"pcapng over one frame", NativeDownloadMetadata{Filename: "artifact-" + id + ".pcapng", Format: PCAPNGFormat, Coverage: "c", Size: RemoteNativeLimit + 1}, false},
		{"pcapng labelled json", NativeDownloadMetadata{Filename: "artifact-" + id + ".json", Format: PCAPNGFormat, Coverage: "c", Size: 1}, false},
		{"unknown format", NativeDownloadMetadata{Filename: "artifact-" + id + ".pcapng", Format: "pcap", Coverage: "c", Size: 1}, false},
		{"multi-line coverage", NativeDownloadMetadata{Filename: "artifact-" + id + ".pcapng", Format: PCAPNGFormat, Coverage: "a\nb", Size: 1}, false},
	} {
		c.m.ETag, c.m.SHA256 = etag, Digest{1}
		q := p
		q.Native = c.m
		if q.Valid() != c.accept {
			t.Error(c.name, "accepted:", !c.accept)
		}
	}
	if nt, _ := LookupNativeType(PCAPNGArtifact); nt.DownloadLimit() != FrameBytes {
		t.Fatal("pcapng download limit", nt.DownloadLimit())
	}
	if nt, _ := LookupNativeType(PodStatusArtifact); nt.DownloadLimit() != MaxContextBytes {
		t.Fatal("pod status download limit", nt.DownloadLimit())
	}
}

func TestProfileNativeDownloadSpansStorageFrames(t *testing.T) {
	const id = "10000000-0000-4000-8000-000000000001"
	for _, name := range []string{PprofArtifact, GoTraceArtifact} {
		typ, ok := LookupNativeType(name)
		if !ok {
			t.Fatal(name)
		}
		if typ.DownloadLimit() != typ.MaxBytes {
			t.Errorf("%s download cap %d truncates declared native limit %d", name, typ.DownloadLimit(), typ.MaxBytes)
		}
		for _, size := range []int64{FrameBytes + 1, typ.MaxBytes} {
			m := NativeDownloadMetadata{Filename: typ.Filename(id), Format: typ.Format, Coverage: typ.Coverage, Size: size, SHA256: Digest{1}}
			if !ValidNativeDownloadMetadata(id, m) {
				t.Errorf("%s native metadata rejected at %d bytes", name, size)
			}
			m.Size = typ.MaxBytes + 1
			if ValidNativeDownloadMetadata(id, m) {
				t.Fatal("accepted oversized native profile")
			}
		}
	}
}
