package live

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
)

// sourceHandle stays valid while its source is unchanged: Version binds the
// source's identity and its hard and privacy ends.
type sourceHandle struct {
	ID, Kind string
	Version  string
}

func sourceVersion(source v.Source) string {
	projections := slices.Clone(source.Projections)
	slices.Sort(projections)

	var binding any = source.Binding
	if source.Manual != nil {
		binding = *source.Manual
	}
	digest := hash(struct {
		Root          string
		Binding       any
		Target        authorization.Target
		Kind, Owner   string
		Hard, Privacy time.Time
		Projections   []string
	}{source.Root(), binding, source.Target, source.OwnerKind, source.OwnerID, source.HardUntil.UTC(), source.PrivacyUntil.UTC(), projections})

	return hex.EncodeToString(digest[:16])
}
func (s *Service) sourceHandleMAC(actor identity.Principal, h sourceHandle) ([]byte, error) {
	digest, e := s.account("source-handle", struct {
		Root              string
		Actor             identity.Principal
		ID, Kind, Version string
	}{s.cfg.RootID, actor, h.ID, h.Kind, h.Version})
	if e != nil {
		return nil, e
	}
	return append([]byte(nil), digest[:24]...), nil
}
func (s *Service) encodeSourceHandle(actor identity.Principal, source v.Source) (string, error) {
	h := sourceHandle{source.ID(), source.OwnerKind, sourceVersion(source)}
	mac, e := s.sourceHandleMAC(actor, h)
	if e != nil {
		return "", e
	}
	defer clear(mac)
	prefix := "lv1p"
	if source.Manual != nil {
		prefix = "lv1m"
	}
	return prefix + "." + h.ID + "." + h.Version + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}
func (s *Service) decodeSourceHandle(actor identity.Principal, encoded string) (sourceHandle, error) {
	var h sourceHandle
	parts := strings.Split(encoded, ".")
	if len(parts) != 4 || (parts[0] != "lv1p" && parts[0] != "lv1m") || !authorization.UUID(parts[1]) || len(parts[2]) != 32 || len(parts[3]) != 32 {
		return h, fmt.Errorf("%w: handles:75", v.ErrDenied)
	}
	digest, e := hex.DecodeString(parts[2])
	if e != nil || hex.EncodeToString(digest) != parts[2] {
		return h, fmt.Errorf("%w: handles:83", v.ErrDenied)
	}
	clear(digest)
	h = sourceHandle{ID: parts[1], Kind: "policy", Version: parts[2]}
	if parts[0] == "lv1m" {
		h.Kind = "manualSession"
	}
	actual, e := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if e != nil || len(actual) != 24 {
		return sourceHandle{}, fmt.Errorf("%w: handles:95", v.ErrDenied)
	}
	defer clear(actual)
	expected, e := s.sourceHandleMAC(actor, h)
	defer clear(expected)
	if e != nil || subtle.ConstantTimeCompare(actual, expected) != 1 {
		return sourceHandle{}, fmt.Errorf("%w: handles:101", v.ErrDenied)
	}
	return h, nil
}
