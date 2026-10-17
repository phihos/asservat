package feasibility

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/klauspost/compress/zstd"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Synthetic data only. These tests never open a live capture interface.
func TestStreamingEncryptionAndCompression(t *testing.T) {
	key, e := keyset.NewHandle(streamingaead.AES256GCMHKDF1MBKeyTemplate())
	if e != nil {
		t.Fatal(e)
	}
	a, e := streamingaead.New(key)
	if e != nil {
		t.Fatal(e)
	}
	plain := bytes.Repeat([]byte("synthetic-user-data:0123456789\n"), 150000)
	aad := []byte("synthetic-artifact/immutable-version")
	var cipher bytes.Buffer
	enc, e := a.NewEncryptingWriter(&cipher, aad)
	if e != nil {
		t.Fatal(e)
	}
	z, e := zstd.NewWriter(enc, zstd.WithEncoderConcurrency(1))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = z.Write(plain); e != nil {
		t.Fatal(e)
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	if e = enc.Close(); e != nil {
		t.Fatal(e)
	}
	decode := func(c, b []byte) ([]byte, error) {
		r, e := a.NewDecryptingReader(bytes.NewReader(c), b)
		if e != nil {
			return nil, e
		}
		d, e := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(16<<20))
		if e != nil {
			return nil, e
		}
		defer d.Close()
		return io.ReadAll(io.LimitReader(d, int64(len(plain)+1)))
	}
	got, e := decode(cipher.Bytes(), aad)
	if e != nil || !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip: %v", e)
	}
	bad := bytes.Clone(cipher.Bytes())
	bad[len(bad)/2] ^= 128
	for name, c := range map[string][]byte{"tampered": bad, "truncated": cipher.Bytes()[:cipher.Len()-5]} {
		t.Run(name, func(t *testing.T) {
			if _, e := decode(c, aad); e == nil {
				t.Fatal("invalid ciphertext accepted")
			}
		})
	}
	if _, e := decode(cipher.Bytes(), []byte("wrong-artifact")); e == nil {
		t.Fatal("wrong AAD accepted")
	}
	r, e := a.NewDecryptingReader(bytes.NewReader(cipher.Bytes()), aad)
	if e != nil {
		t.Fatal(e)
	}
	_, seek := r.(io.Seeker)
	_, at := r.(io.ReaderAt)
	t.Logf("plaintext=%d ciphertext=%d; public reader io.Seeker=%v io.ReaderAt=%v", len(plain), cipher.Len(), seek, at)
}
func TestExplicitEd25519JWS(t *testing.T) {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	p := []byte(`{"purpose":"synthetic-feasibility","sequence":1}`)
	h := jws.NewHeaders()
	if e = h.Set(jws.TypeKey, "asservat-internal-work+jws"); e != nil {
		t.Fatal(e)
	}
	s, e := jws.Sign(p, jws.WithKey(jwa.EdDSAEd25519(), priv, jws.WithProtectedHeaders(h)))
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(string(s), ".")
	b, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		t.Fatal(e)
	}
	var header map[string]any
	if e = json.Unmarshal(b, &header); e != nil {
		t.Fatal(e)
	}
	if header["alg"] != "Ed25519" || header["typ"] != "asservat-internal-work+jws" {
		t.Fatalf("wrong header: %s", b)
	}
	got, e := jws.Verify(s, jws.WithKey(jwa.EdDSAEd25519(), pub))
	if e != nil || !bytes.Equal(got, p) {
		t.Fatalf("verify: %v", e)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte("changed"))
	if _, e := jws.Verify([]byte(strings.Join(parts, ".")), jws.WithKey(jwa.EdDSAEd25519(), pub)); e == nil {
		t.Fatal("tamper accepted")
	}
	if _, e := jws.Verify(s, jws.WithKey(jwa.HS256(), []byte("wrong-algorithm"))); e == nil {
		t.Fatal("wrong algorithm accepted")
	}
	t.Log("Explicit RFC 9864 alg works; peer authority and key rotation not tested")
}
func TestNativePCAPNGAndLibpcap(t *testing.T) {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IP{192, 0, 2, 1}, DstIP: net.IP{192, 0, 2, 2}}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 443, SYN: true, Window: 1024}
	if e := tcp.SetNetworkLayerForChecksum(ip); e != nil {
		t.Fatal(e)
	}
	b := gopacket.NewSerializeBuffer()
	if e := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp); e != nil {
		t.Fatal(e)
	}
	p := b.Bytes()
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 0), CaptureLength: len(p), Length: len(p)}
	for expr, want := range map[string]bool{"tcp dst port 443 and host 192.0.2.2": true, "udp port 53": false} {
		f, e := pcap.NewBPF(layers.LinkTypeEthernet, 65535, expr)
		if e != nil {
			t.Fatal(e)
		}
		if f.Matches(ci, p) != want {
			t.Fatal("filter mismatch", expr)
		}
	}
	if _, e := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, "tcp and ((("); e == nil {
		t.Fatal("invalid grammar accepted")
	}
	var out bytes.Buffer
	w, e := pcapgo.NewNgWriter(&out, layers.LinkTypeEthernet)
	if e != nil {
		t.Fatal(e)
	}
	if e = w.WritePacket(ci, p); e != nil {
		t.Fatal(e)
	}
	if e = w.Flush(); e != nil {
		t.Fatal(e)
	}
	r, e := pcapgo.NewNgReader(bytes.NewReader(out.Bytes()), pcapgo.DefaultNgReaderOptions)
	if e != nil {
		t.Fatal(e)
	}
	got, info, e := r.ReadPacketData()
	if e != nil || !bytes.Equal(got, p) || info.CaptureLength != len(p) {
		t.Fatalf("PCAPNG: %v", e)
	}
	t.Logf("%s; PCAPNG bytes=%d; no interface opened", pcap.Version(), out.Len())
}
