package postgres

import (
	"bytes"
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/capture"
)

var _ app.PolicyAcceptanceLedger = (*Policies)(nil)

func (s *Policies) PendingPolicyAcceptances(ctx context.Context) ([]audit.PolicyAcceptance, error) {
	var out []audit.PolicyAcceptance
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.PendingPolicyAcceptances(ctx, id(s.root))
		if err != nil {
			return err
		}
		out = nil
		for _, row := range rows {
			r, err := decodePolicy(row)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, captureError(err)
	}
	return out, nil
}
func (s *Policies) AcknowledgePolicyAcceptance(ctx context.Context, r audit.PolicyAcceptance, receipt audit.Receipt) error {
	if !r.Valid() || r.RootID != s.root || r.Authority.InstallationID != s.installation || !receipt.ValidPolicyAcceptance(r.RootID, r.ID) {
		return value.ErrInvalid
	}
	return captureError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		// Acknowledgement remains possible after revocation/expiry. It cannot restore
		// source freshness, alter frozen facts or remove a consumed submission nonce.
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		row, err := q.LockPolicyAcceptance(ctx, custodydb.LockPolicyAcceptanceParams{RootID: id(s.root), ID: id(r.ID)})
		if err != nil {
			return err
		}
		frozen, err := decodePolicy(row)
		if err != nil {
			return err
		}
		if !bytes.Equal(digest(frozen), digest(r)) {
			return value.ErrChanged
		}
		if row.AcknowledgedAt.Valid {
			var old audit.Receipt
			if json.Unmarshal(row.ReceiptJson, &old) != nil || old != receipt {
				return value.ErrChanged
			}
			return nil
		}
		encoded, err := json.Marshal(receipt)
		if err != nil {
			return err
		}
		n, err := q.AcknowledgePolicyAcceptance(ctx, custodydb.AcknowledgePolicyAcceptanceParams{RootID: id(s.root), ID: id(r.ID), ReceiptJson: encoded})
		if err != nil {
			return err
		}
		if n != 1 {
			return value.ErrChanged
		}
		return nil
	}))
}
