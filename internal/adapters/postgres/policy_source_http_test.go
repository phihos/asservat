package postgres

import (
	"encoding/json"
	"os"
	"testing"

	compiler "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/planning"
)

// The application compiler is real; the libpcap mechanism program is a fixed
// test pin. This does not qualify source grants or actual HTTP reassembly.
type sourceHTTPFilter struct{}

func (sourceHTTPFilter) CompileFilter(string) (value.CompiledFilter, error) {
	return value.CompiledFilter{LinkType: value.FilterLinkType, Snaplen: value.FilterSnaplen, Program: []value.BPFInstruction{{Code: 6, K: 65535}}}, nil
}
func TestPolicySourceAcceptsOnlyExplicitCompiledReviewedHTTP(t *testing.T) {
	check, now := sourceRetentionCheckFixture(t, 120, 20)
	raw, err := os.ReadFile("../../application/planning/profiles/network-connections-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("catalog fixture")
	}
	doc["name"] = "raw-capture"
	a := doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)
	a["impact"] = "sensitiveRead"
	params := a["parameters"].(map[string]any)
	params["filter"] = "tcp port 8080"
	params["profile"] = map[string]any{"kind": "httpHeaders", "protocol": "http1", "projectionRef": map[string]any{"name": "http-response-headers", "version": "v1"}, "maxFlows": 16, "maxHeaderBytes": 4096, "maxReassemblyBytesPerFlow": 65536, "maxReassemblyBytes": 1048576, "idleTimeout": "5s"}
	body, _ := json.Marshal(doc)
	ref := value.ProfileRef{Catalog: "namespace", Name: "raw-capture", Version: "v1"}
	composition := value.ProfileComposition{Components: []value.ProfileComponent{{ID: "net", Profile: ref}}, Resolved: []value.CatalogProfile{{Ref: ref, SourceClusterID: check.Authority.ClusterID, SourceNamespaceUID: check.Authority.NamespaceUID, SourceUID: "http-profile", Document: body, Enabled: true}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
	recorder, err := compiler.CompileOngoingPolicyRecorder(composition, sourceHTTPFilter{})
	if err != nil {
		t.Fatal("real source compiler", err)
	}
	check.Policy.Recorder = &recorder
	if !sourceCheckCurrent(check, now) {
		t.Fatal("explicit reviewed HTTP source refused before grant transaction")
	}
	for name, edit := range map[string]func(*value.PolicyRecorderConfiguration){"no-bounds": func(p *value.PolicyRecorderConfiguration) { p.HTTP = nil }, "wrong-purpose": func(p *value.PolicyRecorderConfiguration) { p.Action.PacketProfile = "rawPackets" }, "missing-sensitive": func(p *value.PolicyRecorderConfiguration) { p.Action.Sensitive = nil }, "finite": func(p *value.PolicyRecorderConfiguration) { p.Action.ExecutionMode = "onTrigger" }} {
		t.Run(name, func(t *testing.T) {
			p := recorder
			edit(&p)
			in := check
			in.Policy.Recorder = &p
			if sourceCheckCurrent(in, now) {
				t.Fatal("unreviewed or wrong-purpose HTTP source accepted")
			}
		})
	}
}
