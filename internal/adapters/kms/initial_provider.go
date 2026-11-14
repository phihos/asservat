package kms

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"time"

	"asservat.local/asservat/internal/contracts"
	bao "github.com/openbao/openbao/api/v2"
)

// InitialProviderIssuer is installation-only. The caller must persist its
// original one-use issue claim before Issue, own/join each call, and never replay
// it after an unknown response. Check and Verify are read-only and cannot recover
// the secret from an accessor. No KMS administrator token enters the target Pod.
type InitialProviderIssuer struct {
	client                            *bao.Client
	profile                           contracts.InitialProviderProfile
	installation, request, mount, key string
	now                               func() time.Time
	bundled                           *contracts.BundledInitialProviderIdentity
}

func initialProviderFields(raw []byte, names ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, name := range names {
		v, ok := fields[name]
		if !ok || len(v) == 0 || string(v) == "null" {
			return false
		}
	}
	return true
}
func initialProviderDecode(raw []byte, out any) bool {
	if len(raw) == 0 || !jsontext.Value(raw).IsValid() {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out) == nil && d.Decode(new(any)) == io.EOF
}

type initialTokenLookup struct {
	ID               string            `json:"id"`
	Accessor         string            `json:"accessor"`
	Policies         []string          `json:"policies"`
	IdentityPolicies []string          `json:"identity_policies"`
	Path             string            `json:"path"`
	Meta             map[string]string `json:"meta"`
	Display          string            `json:"display_name"`
	Uses             int64             `json:"num_uses"`
	Orphan           bool              `json:"orphan"`
	Creation         int64             `json:"creation_time"`
	CreationTTL      int64             `json:"creation_ttl"`
	Expire           time.Time         `json:"expire_time"`
	TTL              int64             `json:"ttl"`
	MaxTTL           int64             `json:"explicit_max_ttl"`
	Entity           string            `json:"entity_id"`
	Type             string            `json:"type"`
	Role             string            `json:"role"`
	Period           int64             `json:"period"`
	Bound            []string          `json:"bound_cidrs"`
	Renewable        bool              `json:"renewable"`
	Issued           time.Time         `json:"issue_time"`
	LastRenewal      int64             `json:"last_renewal_time"`
	LastRenewalDate  time.Time         `json:"last_renewal"`
}

type initialACLRule struct {
	Capabilities []string `json:"capabilities"`
}
type initialACL struct {
	Path map[string]initialACLRule `json:"path"`
}
