package planning

import (
	"strings"
	"testing"
)

func endpointDefinitionFixture() GoEndpointDefinition {
	s := GoEndpointSource{ClusterID: "11111111-1111-4111-8111-111111111111", ResourceUID: "22222222-2222-4222-8222-222222222222", Name: "pprof", Digest: [32]byte{1}}
	return GoEndpointDefinition{Source: s, PathPolicy: GoEndpointPathPolicy, Host: "pprof.example.invalid:6060", AddressModes: []string{"targetLoopback", "podIP"}, MinimumPort: 6000, MaximumPort: 6999, LoopbackFamily: "ipv4"}
}

func TestGoEndpointDefinitionRejectsUnsafeConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*GoEndpointDefinition)
	}{
		{"path-override", func(d *GoEndpointDefinition) { d.PathPolicy = "/debug/pprof/../../metadata" }},
		{"URL-host", func(d *GoEndpointDefinition) { d.Host = "https://pprof.example.invalid" }},
		{"host-header", func(d *GoEndpointDefinition) { d.Host = "pprof\r\nAuthorization: secret" }},
		{"unicode-host", func(d *GoEndpointDefinition) { d.Host = "profíle.example.invalid" }},
		{"zone-address", func(d *GoEndpointDefinition) { d.Host = "[fe80::1%eth0]:6060" }},
		{"zero-port", func(d *GoEndpointDefinition) { d.MinimumPort = 0 }},
		{"reversed-ports", func(d *GoEndpointDefinition) { d.MinimumPort = 7000 }},
		{"unknown-mode", func(d *GoEndpointDefinition) { d.AddressModes = []string{"collectorLoopback"} }},
		{"duplicate-mode", func(d *GoEndpointDefinition) { d.AddressModes = []string{"podIP", "podIP"} }},
		{"implicit-family", func(d *GoEndpointDefinition) { d.LoopbackFamily = "" }},
		{"unknown-family", func(d *GoEndpointDefinition) { d.LoopbackFamily = "auto" }},
		{"unbound-definition", func(d *GoEndpointDefinition) { d.Source.Digest = [32]byte{} }},
		{"credential-without-TLS", func(d *GoEndpointDefinition) { d.Credential = &GoEndpointCredential{Policy: d.Source} }},
		{"TLS-with-system-trust", func(d *GoEndpointDefinition) { d.TLS = &GoEndpointTLS{ServerName: "pprof.example.invalid"} }},
		{"TLS-wildcard-target", func(d *GoEndpointDefinition) {
			d.TLS = &GoEndpointTLS{Trust: d.Source, ServerName: "*.example.invalid"}
		}},
		{"credential-without-audience", func(d *GoEndpointDefinition) {
			d.TLS = &GoEndpointTLS{Trust: d.Source, ServerName: "pprof.example.invalid"}
			d.Credential = &GoEndpointCredential{Policy: d.Source}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := endpointDefinitionFixture()
			if !d.Valid() {
				t.Fatal("fixture")
			}
			tc.change(&d)
			if d.Valid() {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	for _, host := range []string{"pprof.example.invalid", "127.0.0.1:6060", "[::1]:6060", "[::1]"} {
		d := endpointDefinitionFixture()
		d.Host = host
		if !d.Valid() {
			t.Fatalf("valid Host rejected: %s", host)
		}
	}
}

func TestGoEndpointBindingsKeepExistingRecipeShape(t *testing.T) {
	b := GoEndpointBinding{Name: "local-pprof", TemplateRef: "go-pprof-loopback", AddressMode: "targetLoopback", PortName: "diagnostics"}
	if !b.Valid() {
		t.Fatal("existing recipe binding invalid")
	}
	for _, port := range []string{"6060", "Diagnostics", "diagnostics-too-long", "debug/http", "debug_1", ""} {
		b.PortName = port
		if b.Valid() {
			t.Fatalf("invalid port name %q", port)
		}
	}
}

func TestGoEndpointReferenceUsesDocumentedInternalStringBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"local-pprof", true},
		{"local pprof", true}, // Public schemas impose no DNS-label pattern.
		{"évidence", true},
		{strings.Repeat("a", 63), true},
		{strings.Repeat("é", 31) + "a", true},
		{"", false},
		{strings.Repeat("a", 64), false},
		{strings.Repeat("é", 32), false}, // Explicit internal byte-limit narrowing.
		{"profile\nother", false},
		{"profile\x00other", false},
		{string([]byte{0xff}), false},
	} {
		if GoEndpointReference(tc.name) != tc.valid {
			t.Fatalf("reference bound for %q", tc.name)
		}
		b := GoEndpointBinding{Name: tc.name, TemplateRef: "pprof", AddressMode: "podIP", PortName: "diagnostics"}
		if b.Valid() != tc.valid {
			t.Fatalf("binding name bound for %q", tc.name)
		}
		b.Name, b.TemplateRef = "local", tc.name
		if b.Valid() != tc.valid {
			t.Fatalf("template reference bound for %q", tc.name)
		}
	}
}

func TestGoEndpointHostSyntax(t *testing.T) {
	for _, tc := range []struct {
		name, host string
		valid      bool
	}{
		{"DNS", "pprof.example.invalid", true},
		{"DNS-port", "pprof.example.invalid:6060", true},
		{"single-label", "a", true},
		{"digit-label", "3-pprof", true},
		{"maximum-label", strings.Repeat("a", 63) + ".invalid", true},
		{"IPv4", "127.0.0.1", true},
		{"IPv4-port", "127.0.0.1:6060", true},
		{"minimum-port", "pprof:1", true},
		{"maximum-port", "pprof:65535", true},
		{"IPv6", "[::1]", true},
		{"IPv6-port", "[::1]:6060", true},
		{"expanded-IPv6", "[2001:0DB8:0000:0000:0000:0000:0000:0001]:6060", true},
		{"empty", "", false},
		{"empty-host", ":6060", false},
		{"empty-port", "pprof:", false},
		{"zero-port", "pprof:0", false},
		{"leading-zero-port", "pprof:06060", false},
		{"positive-sign-port", "pprof:+6060", false},
		{"negative-port", "pprof:-1", false},
		{"overflow-port", "pprof:65536", false},
		{"huge-port", "pprof:18446744073709551616", false},
		{"named-port", "pprof:http", false},
		{"extra-port", "pprof:6060:6061", false},
		{"bare-IPv6", "::1", false},
		{"bare-IPv6-port-ambiguity", "2001:db8::1:6060", false},
		{"missing-close-bracket", "[::1:6060", false},
		{"missing-open-bracket", "::1]:6060", false},
		{"extra-open-bracket", "[[::1]:6060", false},
		{"extra-close-bracket", "[::1]]:6060", false},
		{"missing-port-separator", "[::1]6060", false},
		{"bracketed-empty-port", "[::1]:", false},
		{"bracketed-zero-port", "[::1]:0", false},
		{"bracketed-leading-zero-port", "[::1]:06060", false},
		{"bracketed-overflow-port", "[::1]:65536", false},
		{"bracketed-empty-host", "[]:6060", false},
		{"bracketed-DNS", "[pprof]:6060", false},
		{"bracketed-IPv4", "[127.0.0.1]:6060", false},
		{"zone", "[fe80::1%eth0]:6060", false},
		{"mapped-IPv4", "[::ffff:127.0.0.1]:6060", false},
		{"unspecified-IPv6", "[::]:6060", false},
		{"multicast-IPv6", "[ff02::1]:6060", false},
		{"uppercase-DNS", "Pprof.example.invalid", false},
		{"non-ASCII-DNS", "profíle.example.invalid", false},
		{"leading-hyphen", "-pprof.invalid", false},
		{"trailing-hyphen", "pprof-.invalid", false},
		{"empty-label", "pprof..invalid", false},
		{"trailing-dot", "pprof.invalid.", false},
		{"long-label", strings.Repeat("a", 64) + ".invalid", false},
		{"long-host", strings.Repeat("a", 253) + ":1", false},
		{"header-injection", "pprof\r\nX-Secret: value", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := endpointDefinitionFixture()
			d.Host = tc.host
			if d.Valid() != tc.valid {
				t.Fatalf("Host syntax %q accepted=%t want=%t", tc.host, d.Valid(), tc.valid)
			}
		})
	}
}
