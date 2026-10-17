package mtls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"net/url"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

type testCSRInfo struct {
	Version    int
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Attributes []asn1.RawValue `asn1:"tag:0"`
}
type testCSR struct {
	Info      asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

func TestEnrollmentKeyProofAndNoRequestedIdentity(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, mode := range []string{"valid", "common-name", "uri", "extension", "signature", "trailing", "oversize", "ignored-attribute"} {
		t.Run(mode, func(t *testing.T) {
			template := &x509.CertificateRequest{}
			switch mode {
			case "common-name":
				template.Subject.CommonName = "administrator"
			case "uri":
				u, _ := url.Parse("spiffe://untrusted.invalid/identity")
				template.URIs = []*url.URL{u}
			case "extension":
				template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
			}
			der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "signature":
				der[len(der)-1] ^= 1
			case "trailing":
				der = append(der, 0)
			case "oversize":
				der = make([]byte, 8193)
			case "ignored-attribute":
				// PKCS#9 challengePassword is valid ASN.1, but Go's parsed legacy
				// Attributes slice omits this non-RDN-shaped value. Reject it raw.
				var csr testCSR
				_, err = asn1.Unmarshal(der, &csr)
				if err != nil {
					t.Fatal(err)
				}
				var info testCSRInfo
				_, err = asn1.Unmarshal(csr.Info.FullBytes, &info)
				if err != nil {
					t.Fatal(err)
				}
				attribute, err := asn1.Marshal(struct {
					ID     asn1.ObjectIdentifier
					Values []string `asn1:"set"`
				}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, []string{"synthetic-secret"}})
				if err != nil {
					t.Fatal(err)
				}
				info.Attributes = []asn1.RawValue{{FullBytes: attribute}}
				encoded, err := asn1.Marshal(info)
				if err != nil {
					t.Fatal(err)
				}
				csr.Info = asn1.RawValue{FullBytes: encoded}
				sig := ed25519.Sign(key, encoded)
				csr.Signature = asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}
				der, err = asn1.Marshal(csr)
				if err != nil {
					t.Fatal(err)
				}
				parsed, e := x509.ParseCertificateRequest(der)
				if e != nil || parsed.CheckSignature() != nil || len(parsed.Attributes) != 0 {
					t.Fatal("fixture not a valid ignored attribute", e)
				}
			}
			digest, err := EnrollmentKey(der)
			if mode == "valid" {
				if err != nil || digest == (artifact.Digest{}) {
					t.Fatal(digest, err)
				}
			} else if err == nil {
				t.Fatal("unsafe CSR accepted", mode)
			}
		})
	}
}
func TestEnrollmentKeySupportedKeysAndStableRetry(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, key := range []any{ed, ec, rsaKey} {
		a, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if e != nil {
			t.Fatal(e)
		}
		b, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if e != nil {
			t.Fatal(e)
		}
		first, e := EnrollmentKey(a)
		if e != nil {
			t.Fatal(e)
		}
		second, e := EnrollmentKey(b)
		if e != nil || first != second {
			t.Fatal("new CSR signature changed enrollment key")
		}
	}
}
func TestBootstrapSecretDomain(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	const other = "22222222-2222-4222-8222-222222222222"
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	encoded := base64.RawURLEncoding.EncodeToString(secret)
	a, e := BootstrapDigest(id, id, encoded)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := BootstrapDigest(id, other, encoded)
	c, _ := BootstrapDigest(other, id, encoded)
	if a == b || a == c || b == c {
		t.Fatal("bootstrap hash domains overlap")
	}
	for _, s := range []string{"", encoded + "=", encoded[:42], encoded[:42] + "+"} {
		if _, e := BootstrapDigest(id, id, s); e == nil {
			t.Fatal("bad secret accepted")
		}
	}
}
