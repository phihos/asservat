package kms

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"net/http"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	port "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	bao "github.com/openbao/openbao/api/v2"
)

// BootstrapChannel uses a fixed KV-v2 mount/prefix with create/read-only ACLs.
// It cannot overwrite versions, list credentials, undelete or delete metadata.
// Runtime wiring must independently qualify the encrypted provider/channel.
type BootstrapChannel struct {
	client                               *bao.Client
	mount, prefix, profile, installation string
	now                                  func() time.Time
}

var _ port.BootstrapCredentials = (*BootstrapChannel)(nil)

func NewBootstrapChannel(endpoint, token, mount, prefix, profile, installation string, h *http.Client, now func() time.Time) (*BootstrapChannel, error) {
	if !keyName.MatchString(mount) || !keyName.MatchString(prefix) || !keyName.MatchString(profile) || len(profile) > 64 || !authorization.UUID(installation) || now == nil {
		return nil, value.ErrInvalid
	}
	c, err := client(endpoint, token, h)
	if err != nil {
		return nil, err
	}
	return newBootstrapChannelWithClient(c, mount, prefix, profile, installation, now)
}

// newBootstrapChannelWithClient uses an already confined provider client,
// such as the owner's borrowed bootstrap-channel lifetime.
func newBootstrapChannelWithClient(c *bao.Client, mount, prefix, profile, installation string, now func() time.Time) (*BootstrapChannel, error) {
	if c == nil || !keyName.MatchString(mount) || !keyName.MatchString(prefix) || !keyName.MatchString(profile) || len(profile) > 64 || !authorization.UUID(installation) || now == nil {
		return nil, value.ErrInvalid
	}
	return &BootstrapChannel{c, mount, prefix, profile, installation, now}, nil
}

type bootstrapBinding struct {
	Format          string `json:"format"`
	InstallationID  string `json:"installationID"`
	BootstrapID     string `json:"bootstrapID"`
	ClusterID       string `json:"clusterID"`
	PeerID          string `json:"peerID"`
	IssuerEpoch     string `json:"issuerEpoch"`
	DeliveryProfile string `json:"deliveryProfile"`
	RequestDigest   string `json:"requestSHA256"`
	NotBefore       string `json:"notBefore"`
	NotAfter        string `json:"notAfter"`
}
type bootstrapSecret struct {
	Binding bootstrapBinding `json:"binding"`
	Secret  string           `json:"secret"`
}

func slotBinding(s value.BootstrapSlot) bootstrapBinding {
	return bootstrapBinding{Format: "asservat-bootstrap-secret/v1", InstallationID: s.Binding.InstallationID, BootstrapID: s.ID, ClusterID: s.Binding.ClusterID, PeerID: s.Binding.PeerID, IssuerEpoch: s.Binding.IssuerEpoch, DeliveryProfile: s.DeliveryProfile, RequestDigest: hex.EncodeToString(s.RequestDigest[:]), NotBefore: s.NotBefore.UTC().Format(time.RFC3339Nano), NotAfter: s.NotAfter.UTC().Format(time.RFC3339Nano)}
}
func (c *BootstrapChannel) valid(s value.BootstrapSlot) bool {
	return c != nil && c.client != nil && c.now != nil && s.Valid(c.now()) && s.Binding.InstallationID == c.installation && s.DeliveryProfile == c.profile
}
func (c *BootstrapChannel) read(ctx context.Context, s value.BootstrapSlot, path string) (value.BootstrapCredential, bool, error) {
	var out value.BootstrapCredential
	response, err := c.client.RawRequestWithContext(ctx, c.client.NewRequest(http.MethodGet, path))
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if response != nil && response.StatusCode == http.StatusNotFound {
		return out, false, nil
	}
	if err != nil || response == nil || response.StatusCode != http.StatusOK {
		return out, false, ErrKeyService
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	defer clear(body)
	if err != nil || len(body) > 16384 || !jsontext.Value(body).IsValid() {
		return out, false, ErrKeyService
	}
	var reply struct {
		Data struct {
			Data     json.RawMessage `json:"data"`
			Metadata struct {
				Version      int    `json:"version"`
				Destroyed    bool   `json:"destroyed"`
				DeletionTime string `json:"deletion_time"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &reply) != nil || reply.Data.Metadata.Version != 1 || reply.Data.Metadata.Destroyed {
		return out, false, ErrKeyService
	}
	defer clear(reply.Data.Data)
	if d := reply.Data.Metadata.DeletionTime; d != "" {
		until, err := time.Parse(time.RFC3339Nano, d)
		if err != nil || !c.now().Before(until) {
			return out, false, ErrKeyService
		}
	}
	var secret bootstrapSecret
	decoder := json.NewDecoder(bytes.NewReader(reply.Data.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&secret) != nil || secret.Binding != slotBinding(s) {
		return out, false, value.ErrDenied
	}
	// encoding/json accepts case-insensitive struct-field aliases. Compare
	// canonical JSON with the exact owned DTO to reject aliases/missing fields
	// while allowing harmless formatting and object-member ordering changes.
	expected, err := json.Marshal(secret)
	if err != nil {
		return out, false, ErrKeyService
	}
	defer clear(expected)
	actualJSON, expectedJSON := jsontext.Value(reply.Data.Data), jsontext.Value(expected)
	if actualJSON.Canonicalize() != nil || expectedJSON.Canonicalize() != nil || !bytes.Equal(actualJSON, expectedJSON) {
		return out, false, value.ErrDenied
	}
	digest, err := mtls.BootstrapDigest(c.installation, s.ID, secret.Secret)
	if err != nil {
		return out, false, value.ErrDenied
	}
	if !c.valid(s) || ctx.Err() != nil {
		return out, false, value.ErrDenied
	}
	return value.BootstrapCredential{SlotID: s.ID, DeliveryProfile: c.profile, SecretDigest: digest, Version: 1}, true, nil
}
func (c *BootstrapChannel) EnsureBootstrapCredential(ctx context.Context, s value.BootstrapSlot) (value.BootstrapCredential, error) {
	var out value.BootstrapCredential
	if !c.valid(s) {
		return out, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	path := "/v1/" + c.mount + "/data/" + c.prefix + "/" + c.installation + "/" + s.ID
	existing, found, err := c.read(ctx, s, path)
	if err != nil {
		return out, err
	}
	if found {
		return existing, nil
	}
	if !c.valid(s) || ctx.Err() != nil {
		return out, value.ErrDenied
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return out, ErrKeyService
	}
	defer clear(raw)
	record := bootstrapSecret{Binding: slotBinding(s), Secret: base64.RawURLEncoding.EncodeToString(raw)}
	request := c.client.NewRequest(http.MethodPost, path)
	if err = request.SetJSONBody(map[string]any{"options": map[string]int{"cas": 0}, "data": record}); err != nil {
		return out, ErrKeyService
	}
	// One write only. A lost response or concurrent creator is resolved by one
	// authenticated read; never overwrite, retry the POST, or extend expiry.
	response, _ := c.client.RawRequestWithContext(ctx, request)
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	existing, found, err = c.read(ctx, s, path)
	if err != nil {
		return out, err
	}
	if !found {
		return out, ErrKeyService
	}
	return existing, nil
}

// DecodeBootstrapRecord parses the KV record an operator read from the
// bootstrap channel (its data object) into the connector's one-use envelope
// (ADR-193). It applies the channel's own strict spelling and secret checks;
// it confers nothing until the hub claims the slot.
func DecodeBootstrapRecord(raw []byte) (value.BootstrapEnvelope, error) {
	var zero value.BootstrapEnvelope
	var secret bootstrapSecret
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 16<<10 || decoder.Decode(&secret) != nil || decoder.More() {
		return zero, value.ErrInvalid
	}
	expected, err := json.Marshal(secret)
	if err != nil {
		return zero, value.ErrInvalid
	}
	defer clear(expected)
	actual, canonical := jsontext.Value(bytes.Clone(raw)), jsontext.Value(expected)
	defer clear(actual)
	b := secret.Binding
	if actual.Canonicalize() != nil || canonical.Canonicalize() != nil || !bytes.Equal(actual, canonical) || b.Format != "asservat-bootstrap-secret/v1" {
		return zero, value.ErrInvalid
	}
	request, err := hex.DecodeString(b.RequestDigest)
	notBefore, berr := time.Parse(time.RFC3339Nano, b.NotBefore)
	notAfter, aerr := time.Parse(time.RFC3339Nano, b.NotAfter)
	if err != nil || berr != nil || aerr != nil || len(request) != 32 {
		return zero, value.ErrInvalid
	}
	if _, err = mtls.BootstrapDigest(b.InstallationID, b.BootstrapID, secret.Secret); err != nil {
		return zero, value.ErrInvalid
	}
	out := value.BootstrapEnvelope{BootstrapID: b.BootstrapID, Binding: value.PeerBinding{InstallationID: b.InstallationID, ClusterID: b.ClusterID, PeerID: b.PeerID, IssuerEpoch: b.IssuerEpoch, Role: value.ConnectorPeer},
		DeliveryProfile: b.DeliveryProfile, RequestDigest: artifact.Digest(request), NotBefore: notBefore.UTC(), NotAfter: notAfter.UTC(), Secret: secret.Secret}
	if !out.Valid() {
		return zero, value.ErrInvalid
	}
	return out, nil
}
