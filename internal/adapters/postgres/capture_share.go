package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// captureShareWire is context_capture.share_instruction (migration 00088,
// ADR-235). Publication's owner-privileged trigger copies these fields into
// exactly one evidence_share row; the share ledger decodes that row as usual.
type captureShareWire struct {
	ShareID       string                        `json:"share_id"`
	Creator       captureShareCreator           `json:"creator"`
	Management    []artifact.AudienceAssignment `json:"management"`
	Recipients    []shareRecipientWire          `json:"recipients"`
	RecipientKeys []string                      `json:"recipient_keys"`
	NotAfter      *time.Time                    `json:"not_after"`
	RequestDigest string                        `json:"request_digest"`
}

type captureShareCreator struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Client  string `json:"client"`
}

// captureShareInstruction pins a reviewed capture-time sharing instruction
// inside the admission transaction, after its locks. The requester must hold
// evidence-owner and evidence:share on the same SQL projection the admission
// evaluates (authorization.ShareManagement, the create_share check); otherwise
// the whole request is refused before any capture exists. A nil instruction
// stores nothing.
func captureShareInstruction(ctx context.Context, q *custodydb.Queries, stream custodydb.PermissionStream, reviewed value.ContextPreview, a value.Admission, audience []artifact.AudienceAssignment) ([]byte, error) {
	s := reviewed.Intent.Sharing
	if s == nil {
		return nil, nil
	}
	i := a.Eligibility.VerifiedIdentity
	if a.RecordingSave != nil {
		i = a.RecordingSave.Initiator.VerifiedIdentity
	}
	target := a.Plan.Input.Target.Target()
	if !s.Valid() || i.Principal != reviewed.Actor || s.Recipients[0].Issuer != i.Principal.Issuer {
		return nil, value.ErrInvalid
	}
	p, err := permissionProjection(ctx, q, stream, target)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return nil, err
	}
	if !s.NotAfter.IsZero() && (!s.NotAfter.After(n.Time) || s.NotAfter.After(n.Time.Add(authorization.ShareMaxLifetime))) {
		return nil, value.ErrInvalid
	}
	r := a.Registration
	retained := authorization.Retained{ArtifactID: r.Location.ArtifactID, Target: target, DataClass: "metadata", ExpiresAt: r.ExpiresAt, Audience: audience}
	if result, owners := authorization.ShareManagement(i, p, target, &retained, n.Time); result.Eligible {
		w := captureShareWire{ShareID: uuid.NewString(), Creator: captureShareCreator{i.Principal.Issuer, i.Principal.Subject, i.Principal.ClientID}, Management: owners}
		for _, x := range s.Recipients {
			w.Recipients = append(w.Recipients, shareRecipientWire{Kind: x.Kind, Issuer: x.Issuer, ID: x.ID})
			w.RecipientKeys = append(w.RecipientKeys, x.Key())
		}
		if !s.NotAfter.IsZero() {
			end := s.NotAfter.UTC()
			w.NotAfter = &end
		}
		request, err := json.Marshal(struct {
			CaptureID  string
			Recipients []shareRecipientWire
			NotAfter   *time.Time
		}{a.Plan.Input.CaptureID, w.Recipients, w.NotAfter})
		if err != nil {
			return nil, value.ErrInvalid
		}
		digest := sha256.Sum256(request)
		w.RequestDigest = hex.EncodeToString(digest[:])
		out, err := json.Marshal(w)
		if err != nil || len(out) > 65536 {
			return nil, value.ErrInvalid
		}
		return out, nil
	}
	return nil, value.ErrSharingDenied
}

// captureShareID returns the share ID of a stored instruction, or "" when the
// accepted capture carries none.
func captureShareID(stored []byte) (string, error) {
	if len(stored) == 0 {
		return "", nil
	}
	var w captureShareWire
	if json.Unmarshal(stored, &w) != nil || !authorization.UUID(w.ShareID) {
		return "", value.ErrUnavailable
	}
	return w.ShareID, nil
}

// CaptureShareExists reports whether publication materialized the
// capture-time share with this ID (ADR-235). It reads only the row's
// existence; recipients' reads evaluate the share itself.
func (s *EvidenceShares) CaptureShareExists(ctx context.Context, shareID string) (bool, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(shareID) {
		return false, value.ErrUnavailable
	}
	_, err := custodydb.New(s.ledger.pool).ReadCaptureShare(ctx, custodydb.ReadCaptureShareParams{RootID: id(s.root), ID: id(shareID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, value.ErrUnavailable
	}
	return true, nil
}
