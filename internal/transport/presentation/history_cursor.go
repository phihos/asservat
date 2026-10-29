package presentation

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"time"
)

type protectedHistoryCursor struct {
	Format   string
	Binding  artifact.Digest
	Position value.HistoryCursor
}

func historyOrigin(origin string) string {
	if origin == "" {
		return "manual"
	}
	return origin
}
func (s *ContextOperations) historyCursorBinding(in ContextOperationInput, i identity.Identity) (artifact.Digest, error) {
	if s.config.HistoryCursorKeys == nil || !authorization.UUID(s.config.HistoryRootID) {
		return artifact.Digest{}, value.ErrHistoryUnavailable
	}
	groups, scopes := slices.Clone(i.Groups), slices.Clone(i.Scopes)
	slices.Sort(groups)
	slices.Sort(scopes)
	b, err := json.Marshal(struct {
		Purpose, Root  string
		Principal      identity.Principal
		Policy         identity.Revision
		Groups, Scopes []string
		Target         WorkloadReference
		Origin         string
	}{"history-cursor-binding/v2", s.config.HistoryRootID, i.Principal, i.Policy, groups, scopes, in.Target, historyOrigin(in.Origin)})
	if err != nil {
		return artifact.Digest{}, value.ErrInvalid
	}
	defer clear(b)
	return s.config.HistoryCursorKeys.HistoryDigest("cursor", b)
}
func (s *ContextOperations) encodeHistoryCursor(in ContextOperationInput, actor identity.Identity, page value.HistoryPage, after *value.HistoryCursor) (*string, error) {
	if page.Next == nil {
		return nil, nil
	}
	binding, err := s.historyCursorBinding(in, actor)
	if err != nil {
		return nil, err
	}
	if !page.Target.Valid() || !page.AuthorizationRevision.Valid() {
		return nil, value.ErrHistoryUnavailable
	}
	position := *page.Next
	position.Target = page.Target
	position.SnapshotBefore = page.SnapshotBefore
	if position.SnapshotBefore.IsZero() {
		position.SnapshotBefore = s.config.Now().UTC().Truncate(time.Microsecond)
	}
	position.ExpiresAt = position.SnapshotBefore.Add(15 * time.Minute)
	if after != nil {
		position.ExpiresAt = after.ExpiresAt
	}
	position.AuthorizationRevision = page.AuthorizationRevision
	body, err := json.Marshal(protectedHistoryCursor{Format: "history/v2", Binding: binding, Position: position})
	if err != nil || len(body) > 2048 {
		return nil, value.ErrHistoryUnavailable
	}
	defer clear(body)
	tag, err := s.config.HistoryCursorKeys.HistoryDigest("cursor", body)
	if err != nil {
		return nil, value.ErrHistoryUnavailable
	}
	token := base64.RawURLEncoding.EncodeToString(body) + "." + hex.EncodeToString(tag[:])
	if len(token) > 4096 {
		return nil, value.ErrHistoryUnavailable
	}
	return &token, nil
}
func (s *ContextOperations) decodeHistoryCursor(in ContextOperationInput, actor identity.Identity) (*value.HistoryCursor, error) {
	if in.Cursor == "" {
		return nil, nil
	}
	if len(in.Cursor) > 4096 {
		return nil, value.ErrInvalid
	}
	binding, err := s.historyCursorBinding(in, actor)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(in.Cursor, ".")
	if len(parts) != 2 {
		return nil, value.ErrInvalid
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(body) > 2048 {
		return nil, value.ErrInvalid
	}
	defer clear(body)
	supplied, err := hex.DecodeString(parts[1])
	if err != nil || len(supplied) != 32 {
		return nil, value.ErrInvalid
	}
	tag, err := s.config.HistoryCursorKeys.HistoryDigest("cursor", body)
	if err != nil || !hmac.Equal(tag[:], supplied) {
		return nil, value.ErrInvalid
	}
	var token protectedHistoryCursor
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&token) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, value.ErrInvalid
	}
	p := token.Position
	now := s.config.Now()
	if !p.Target.Valid() || !p.AuthorizationRevision.Valid() || token.Format != "history/v2" || !hmac.Equal(token.Binding[:], binding[:]) || !authorization.UUID(p.CaptureID) || p.AcceptedAt.IsZero() || p.SnapshotBefore.IsZero() || p.SnapshotBefore.After(now) || p.AcceptedAt.After(p.SnapshotBefore) || !now.Before(p.ExpiresAt) || p.ExpiresAt.After(p.SnapshotBefore.Add(15*time.Minute)) {
		return nil, value.ErrInvalid
	}
	return &p, nil
}
