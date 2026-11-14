package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	port "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type BootstrapReservations struct {
	claims *EnrollmentClaims
	newID  func() string
	// local is the combined-mode connector's fixed generated cluster and
	// peer (NewLocalBootstrapReservations); nil reserves fresh random IDs.
	local *[2]string
}

var _ port.BootstrapReservations = (*BootstrapReservations)(nil)

func NewBootstrapReservations(ctx context.Context, pool *pgxpool.Pool, installation string, newID func() string) (*BootstrapReservations, error) {
	if newID == nil {
		return nil, value.ErrInvalid
	}
	c, err := NewEnrollmentClaims(ctx, pool, installation)
	if err != nil {
		return nil, err
	}
	return &BootstrapReservations{claims: c, newID: newID}, nil
}

// NewLocalBootstrapReservations reserves slots only for the installation's
// own connector: the generated cluster and peer IDs. A new slot is reserved
// only after the peer's latest slot expired without activation (unclaimed,
// or claimed by an enrollment that failed); a live slot of the same request
// resumes, a live claimed or other slot returns value.ErrPending and an
// activated enrollment of the peer returns value.ErrLocalBootstrapConsumed.
func NewLocalBootstrapReservations(ctx context.Context, pool *pgxpool.Pool, installation, clusterID, peerID string, newID func() string) (*BootstrapReservations, error) {
	if !authorization.UUID(clusterID) || !authorization.UUID(peerID) || clusterID == peerID {
		return nil, value.ErrInvalid
	}
	r, err := NewBootstrapReservations(ctx, pool, installation, newID)
	if err != nil {
		return nil, err
	}
	r.local = &[2]string{clusterID, peerID}
	return r, nil
}

// localIntent returns the peer's live slot to resume, or nil when a new slot
// may be reserved.
func (r *BootstrapReservations) localIntent(ctx context.Context, q *custodydb.Queries, request value.BootstrapRequest, now time.Time) (*custodydb.FleetBootstrapIntent, error) {
	latest, err := q.LatestPeerBootstrapIntent(ctx, custodydb.LatestPeerBootstrapIntentParams{InstallationID: id(request.Authority.InstallationID), PeerID: id(r.local[1])})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	row := latest.FleetBootstrapIntent
	switch {
	case latest.Activated:
		return nil, value.ErrLocalBootstrapConsumed
	case !now.Before(row.NotAfter.Time):
		// Expired, claimed or not: activation requires an unexpired slot,
		// so the old slot can no longer enroll and a new one may replace it.
		return nil, nil
	case latest.Claimed:
		// The connector's enrollment is in progress; it either activates
		// before expiry or the slot is replaced afterwards.
		return nil, value.ErrPending
	case uid(row.ClusterID) != r.local[0] || !bytes.Equal(row.ActorDigest, digest(request.Authority.Actor)) || !bytes.Equal(row.KeyDigest, request.KeyDigest[:]):
		return nil, value.ErrPending
	case !bytes.Equal(row.RequestDigest, bootstrapRequestDigest(request)):
		return nil, value.ErrConflict
	}
	return &row, nil
}
func bootstrapRequestDigest(r value.BootstrapRequest) []byte {
	return digest(struct {
		Format                        string
		Actor                         identity.Principal
		Name, Region, DeliveryProfile string
	}{"bootstrap-request/v1", r.Authority.Actor, r.DisplayName, r.Region, r.Authority.DeliveryProfile})
}
func checkEnrollmentAuthority(root custodydb.FleetCurrentTrust, a value.EnrollmentAuthority, now time.Time) error {
	if !a.Valid(now) || root.InstallationID != id(a.InstallationID) || root.IssuerEpoch != id(a.IssuerEpoch) || root.Suspended || root.RecoveryBlocked || trustRevision(root) != a.AdministrationRevision || !identity.Fresh(root.ObservedAt.Time, root.FreshUntil.Time, now, 30*time.Second) {
		return value.ErrDenied
	}
	return nil
}
func bootstrapIntent(row custodydb.FleetBootstrapIntent, a value.EnrollmentAuthority, now, until time.Time) (value.BootstrapIntent, error) {
	var out value.BootstrapIntent
	if json.Unmarshal(row.ActorJson, &out.Actor) != nil || out.Actor != a.Actor || !bytes.Equal(row.ActorDigest, digest(a.Actor)) {
		return out, value.ErrDenied
	}
	out.Slot = value.BootstrapSlot{ID: uid(row.ID), Binding: value.PeerBinding{InstallationID: uid(row.InstallationID), ClusterID: uid(row.ClusterID), PeerID: uid(row.PeerID), IssuerEpoch: uid(row.IssuerEpoch), Role: value.ConnectorPeer}, DeliveryProfile: row.DeliveryProfile, NotBefore: row.NotBefore.Time.UTC(), NotAfter: row.NotAfter.Time.UTC(), CheckedAt: now.UTC(), ValidUntil: identity.Earlier(until, row.NotAfter.Time).UTC()}
	copy(out.Slot.RequestDigest[:], row.RequestDigest)
	out.IdentityRevision = identity.Revision{UID: row.IdentityUid, Generation: row.IdentityGeneration}
	copy(out.IdentityRevision.Digest[:], row.IdentityDigest)
	out.AdministrationRevision = identity.Revision{UID: row.TrustUid, Generation: row.TrustGeneration}
	copy(out.AdministrationRevision.Digest[:], row.TrustDigest)
	out.DisplayName, out.Region = row.DisplayName, row.Region
	if row.CredentialRecordedAt.Valid {
		r, err := bootstrapIssue(row)
		if err != nil {
			return value.BootstrapIntent{}, err
		}
		out.Credential = &r.Credential
	}
	out.Issued = row.IssuedAt.Valid
	if !out.Slot.Valid(now) || !out.IdentityRevision.Valid() || out.AdministrationRevision != a.AdministrationRevision || out.Slot.Binding.IssuerEpoch != a.IssuerEpoch || out.Slot.DeliveryProfile != a.DeliveryProfile {
		return value.BootstrapIntent{}, value.ErrDenied
	}
	return out, nil
}
func (r *BootstrapReservations) ReserveBootstrap(ctx context.Context, request value.BootstrapRequest) (value.BootstrapIntent, error) {
	var out value.BootstrapIntent
	a := request.Authority
	if a.InstallationID != r.claims.installation || !request.Valid(a.CheckedAt) {
		return out, value.ErrInvalid
	}
	err := r.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = value.BootstrapIntent{}
		root, err := q.LockFleetTrust(ctx, id(a.InstallationID))
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if err = checkEnrollmentAuthority(root, a, now.Time); err != nil {
			return err
		}
		var row custodydb.FleetBootstrapIntent
		if r.local != nil {
			live, lerr := r.localIntent(ctx, q, request, now.Time)
			if lerr != nil {
				return lerr
			}
			if live != nil {
				row = *live
			} else {
				err = pgx.ErrNoRows
			}
		} else {
			row, err = q.FindBootstrapIntent(ctx, custodydb.FindBootstrapIntentParams{InstallationID: root.InstallationID, ActorDigest: digest(a.Actor), KeyDigest: request.KeyDigest[:]})
		}
		if err == nil {
			if !bytes.Equal(row.RequestDigest, bootstrapRequestDigest(request)) {
				return value.ErrConflict
			}
		} else {
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			count, err := q.CountBootstrapReservations(ctx, custodydb.CountBootstrapReservationsParams{InstallationID: root.InstallationID, CheckTime: now})
			if err != nil {
				return err
			}
			clusters, err := q.CountReservedClusters(ctx, custodydb.CountReservedClustersParams{InstallationID: root.InstallationID, NotAfter: now})
			if err != nil {
				return err
			}
			if count.ActiveCount >= int64(a.MaxActiveBootstraps) || count.HistoryCount >= int64(a.MaxBootstrapHistory) || clusters >= int64(a.MaxClusters) {
				return value.ErrCapacity
			}
			// Counts may have waited behind other database work. Recheck the original
			// authority before establishing the immutable five-minute slot deadline.
			now, err = q.CurrentTime(ctx)
			if err != nil {
				return err
			}
			if err = checkEnrollmentAuthority(root, a, now.Time); err != nil {
				return err
			}
			slotID, clusterID, peerID := r.newID(), r.newID(), r.newID()
			if r.local != nil {
				clusterID, peerID = r.local[0], r.local[1]
			}
			if !authorization.UUID(slotID) || !authorization.UUID(clusterID) || !authorization.UUID(peerID) {
				return value.ErrUnavailable
			}
			actor, err := json.Marshal(a.Actor)
			if err != nil {
				return value.ErrUnavailable
			}
			row, err = q.InsertBootstrapIntent(ctx, custodydb.InsertBootstrapIntentParams{InstallationID: root.InstallationID, ID: id(slotID), ActorDigest: digest(a.Actor), KeyDigest: request.KeyDigest[:], RequestDigest: bootstrapRequestDigest(request), ActorJson: actor, IdentityUid: a.IdentityRevision.UID, IdentityGeneration: a.IdentityRevision.Generation, IdentityDigest: a.IdentityRevision.Digest[:], TrustUid: a.AdministrationRevision.UID, TrustGeneration: a.AdministrationRevision.Generation, TrustDigest: a.AdministrationRevision.Digest[:], ClusterID: id(clusterID), PeerID: id(peerID), IssuerEpoch: root.IssuerEpoch, DeliveryProfile: a.DeliveryProfile, DisplayName: request.DisplayName, Region: request.Region, NotBefore: now, NotAfter: ts(now.Time.Add(5 * time.Minute))})
			if err != nil {
				return err
			}
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if err = checkEnrollmentAuthority(root, a, now.Time); err != nil {
			return err
		}
		out, err = bootstrapIntent(row, a, now.Time, identity.Earlier(a.ValidUntil, root.FreshUntil.Time))
		return err
	})
	if err != nil {
		return value.BootstrapIntent{}, err
	}
	return out, nil
}
