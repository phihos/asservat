package kms_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/domain/artifact"
)

// These fixture backends run in one test process to qualify the byte contract.
// This does not substitute for the future key-service authentication boundary.
func persistentLocalKey(t *testing.T, purpose string) (*kms.LocalKeyBackend, func() *kms.LocalKeyBackend) {
	t.Helper()
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	defer clear(material)
	scope := kms.LocalKeyScope{InstallationID: "00000000-0000-4000-8000-000000000001", Purpose: purpose, KeyID: "fixture-key"}
	secret, err := json.Marshal(map[string]any{
		"format": "asservat-local-keys/v1", "installationID": scope.InstallationID, "purpose": scope.Purpose,
		"keyID": scope.KeyID, "activeVersion": 1,
		"keys": []any{map[string]any{"version": 1, "material": base64.StdEncoding.EncodeToString(material)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(secret) })
	restore := func() *kms.LocalKeyBackend {
		k, err := kms.NewLocalKeyBackend(scope, bytes.NewReader(secret))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	return restore(), restore
}

type localCipherSource []byte

func (s localCipherSource) ReadRange(_ context.Context, offset, length int64) ([]byte, error) {
	if offset < 0 || length < 1 || offset > int64(len(s)) || length > int64(len(s))-offset {
		return nil, io.ErrUnexpectedEOF
	}
	return bytes.Clone(s[offset : offset+length]), nil
}

type localDelivery struct{ bytes.Buffer }

func (d *localDelivery) Send(_ context.Context, b []byte) error {
	if len(b) > 1<<20 {
		return fmt.Errorf("unbounded native delivery")
	}
	_, err := d.Write(b)
	return err
}

func TestLocalKeysPreserveFramedNativeFilesAndRanges(t *testing.T) {
	ctx := context.Background()
	keys, restore := persistentLocalKey(t, "artifact")
	binding := artifact.Binding{
		ClusterID: "00000000-0000-4000-8000-000000000011", ArtifactID: "00000000-0000-4000-8000-000000000012",
		AttemptID: "00000000-0000-4000-8000-000000000013", MediaType: "application/octet-stream",
	}
	for _, size := range []int{0, 733, (8 << 20) + 171} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			plain := make([]byte, size)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}
			defer clear(plain)
			encoder, err := framed.Prepare(ctx, binding, keys)
			if err != nil {
				t.Fatal(err)
			}
			var data, index bytes.Buffer
			layout, err := encoder.Encode(ctx, bytes.NewReader(plain), &data, &index, int64(size))
			if err != nil {
				t.Fatal(err)
			}
			reader, err := framed.Open(ctx, layout, restore(), localCipherSource(data.Bytes()), localCipherSource(index.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			delivery := &localDelivery{}
			if err := reader.Read(ctx, 0, int64(size), delivery); err != nil || !bytes.Equal(delivery.Bytes(), plain) {
				t.Fatal("native readback mismatch", err)
			}
			if size > 8<<20 {
				delivery.Reset()
				offset := int64((8 << 20) - 97)
				if err := reader.Read(ctx, offset, 141, delivery); err != nil || !bytes.Equal(delivery.Bytes(), plain[offset:offset+141]) {
					t.Fatal("cross-frame range mismatch", err)
				}
			}
		})
	}
}

func TestBrowserCredentialsUseProviderPorts(t *testing.T) {
	ctx := context.Background()
	keys, restore := persistentLocalKey(t, "browser-credentials")
	writer := kms.BrowserCipher{Sealer: keys}
	plain, ad := []byte("synthetic access/refresh tokens"), []byte("installation+issuer+client+row+version")
	sealed, err := writer.Encrypt(ctx, plain, ad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("plaintext credential envelope")
	}
	reader := kms.BrowserCipher{Opener: restore()}
	got, err := reader.Decrypt(ctx, sealed, ad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("credential recovery mismatch", err)
	}
	clear(got)
	if b, err := reader.Decrypt(ctx, sealed, []byte("another session")); err == nil || b != nil {
		t.Fatal("foreign session disclosed")
	}
	other, _ := persistentLocalKey(t, "artifact")
	if b, err := (kms.BrowserCipher{Opener: other}).Decrypt(ctx, sealed, ad); err == nil || b != nil {
		t.Fatal("evidence provider decrypted browser credentials")
	}
	if _, err := writer.Decrypt(ctx, sealed, ad); err == nil {
		t.Fatal("write-only credential facet acquired reader")
	}
	if _, err := reader.Encrypt(ctx, plain, ad); err == nil {
		t.Fatal("read-only credential facet acquired writer")
	}
}

func TestBrowserCredentialPortsRejectUnconfiguredProviders(t *testing.T) {
	var nilSealer *kms.Sealer
	var nilOpener *kms.Opener
	var nilLocal *kms.LocalKeyBackend
	malformed, err := json.Marshal(map[string]any{
		"Format": "asservat-browser-credentials/v1", "Ciphertext": []byte{1},
		"Key": artifact.SealedKey{Reference: "transit/key", Ciphertext: "synthetic"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, cipher := range map[string]kms.BrowserCipher{
		"missing":          {},
		"typed-nil-remote": {Sealer: nilSealer, Opener: nilOpener},
		"zero-remote":      {Sealer: &kms.Sealer{}, Opener: &kms.Opener{}},
		"typed-nil-local":  {Sealer: nilLocal, Opener: nilLocal},
		"zero-local":       {Sealer: &kms.LocalKeyBackend{}, Opener: &kms.LocalKeyBackend{}},
	} {
		t.Run(name+"/encrypt", func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Error("unconfigured provider panicked")
				}
			}()
			if b, err := cipher.Encrypt(context.Background(), []byte("synthetic"), []byte("binding")); err == nil || b != nil {
				t.Fatal("unconfigured provider encrypted credentials")
			}
		})
		t.Run(name+"/decrypt", func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Error("unconfigured provider panicked")
				}
			}()
			if b, err := cipher.Decrypt(context.Background(), malformed, []byte("binding")); err == nil || b != nil {
				t.Fatal("unconfigured provider decrypted credentials")
			}
		})
	}
}
