package live

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"time"
)

type sourceHandle struct {
	ID, Kind string
	Until    time.Time
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
		Until             int64
	}{s.cfg.RootID, actor, h.ID, h.Kind, h.Version, h.Until.Unix()})
	if e != nil {
		return nil, e
	}
	return append([]byte(nil), digest[:24]...), nil
}
func (s *Service) encodeSourceHandle(actor identity.Principal, source v.Source, until time.Time) (string, time.Time, error) {
	until = until.UTC().Truncate(time.Second)
	h := sourceHandle{source.ID(), source.OwnerKind, until, sourceVersion(source)}
	mac, e := s.sourceHandleMAC(actor, h)
	if e != nil {
		return "", time.Time{}, e
	}
	defer clear(mac)
	prefix := "lv1p"
	if source.Manual != nil {
		prefix = "lv1m"
	}
	encoded := prefix + "." + h.ID + "." + strconv.FormatInt(until.Unix(), 16) + "." + h.Version + "." + base64.RawURLEncoding.EncodeToString(mac)
	if len(encoded) > 128 {
		return "", time.Time{}, v.ErrInvalid
	}
	return encoded, until, nil
}
func (s *Service) decodeSourceHandle(actor identity.Principal, encoded string) (sourceHandle, error) {
	var h sourceHandle
	parts := strings.Split(encoded, ".")
	if len(encoded) > 128 || len(parts) != 5 || (parts[0] != "lv1p" && parts[0] != "lv1m") || !authorization.UUID(parts[1]) || len(parts[2]) > 11 || len(parts[3]) != 32 || len(parts[4]) != 32 {
		return h, v.ErrDenied
	}
	until, e := strconv.ParseInt(parts[2], 16, 64)
	if e != nil || strconv.FormatInt(until, 16) != parts[2] {
		return h, v.ErrDenied
	}
	digest, e := hex.DecodeString(parts[3])
	if e != nil || hex.EncodeToString(digest) != parts[3] {
		return h, v.ErrDenied
	}
	clear(digest)
	h = sourceHandle{ID: parts[1], Kind: "policy", Until: time.Unix(until, 0).UTC(), Version: parts[3]}
	if parts[0] == "lv1m" {
		h.Kind = "manualSession"
	}
	if !s.cfg.Now().Before(h.Until) || h.Until.After(s.cfg.Now().Add(time.Minute)) {
		return sourceHandle{}, v.ErrDenied
	}
	actual, e := base64.RawURLEncoding.Strict().DecodeString(parts[4])
	if e != nil || len(actual) != 24 {
		return sourceHandle{}, v.ErrDenied
	}
	defer clear(actual)
	expected, e := s.sourceHandleMAC(actor, h)
	defer clear(expected)
	if e != nil || subtle.ConstantTimeCompare(actual, expected) != 1 {
		return sourceHandle{}, v.ErrDenied
	}
	return h, nil
}
