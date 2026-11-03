package artifact

import "testing"

// Profiles use the existing raw grant gate; recognizing their native type is
// never sufficient authority to disclose their bytes.
func TestProfileDeliveryClassAndShape(t *testing.T) {
	for _, typ := range []string{PprofArtifact, GoTraceArtifact} {
		e := typedExpectation(t, typ, 16<<20)
		e.ExecutionClass, e.NodeUID, e.NodeBootID = ContextAPIExecution, "", ""
		e.DataClass = "raw"
		e.Profile = &GoProfileAcquisition{SourceRef: "go", EndpointDigest: Digest{1}, Type: "heap", Mode: "snapshot"}
		if typ == GoTraceArtifact {
			e.Profile.Type, e.Profile.Mode, e.Profile.DurationMillis = "runtimeTrace", "interval", 1000
		}
		if e.Validate() != nil || !e.ServedClass() || !DownloadEvidenceType(e.Type().EvidenceType) {
			t.Fatalf("profile delivery shape refused: %s", typ)
		}
		for _, class := range []string{"metadata", "extract"} {
			x := e
			x.DataClass = class
			if x.Validate() == nil {
				t.Fatalf("profile accepted as %s", class)
			}
		}
		x := e
		x.Profile = nil
		if x.Validate() == nil {
			t.Fatal("native profile without accepted acquisition")
		}
	}
	if (ContextExpectation{NativeType: PCAPNGArtifact, DataClass: "raw"}).ServedClass() {
		t.Fatal("profile addition widened other raw classes")
	}
}
