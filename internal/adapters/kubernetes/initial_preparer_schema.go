package kubernetes

import (
	"encoding/hex"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func (s *InitialPreparer) validSchema(w contracts.InitialPreparationRoot) bool {
	v := w.Schema
	if v == nil {
		return s.plan.SchemaInitialization == "" || len(w.Creates) == 0 && w.Activation == nil
	}
	if s.plan.SchemaInitialization != contracts.InitialSchemaProtocol || w.RootUID == "" || !authorization.UUID(v.AttemptID) || v.Head < 1 || v.Head > contracts.InitialSchemaMaxHead || v.DatabaseOID == 0 || !initialHandoverTime(v.PostmasterAt) || !initialHandoverTime(v.ClaimedAt) || v.PostmasterAt.After(v.ClaimedAt) || !identity.Text(v.DDLRole.Name, 63) || v.DDLRole.OID == 0 || s.plan.HistoryManager == nil || v.Manager != *s.plan.HistoryManager || v.DDLRole.OID == v.Manager.OID {
		return false
	}
	digest, e := hex.DecodeString(v.BundleDigest)
	if e != nil || len(digest) != 32 || hex.EncodeToString(digest) != v.BundleDigest {
		return false
	}
	if v.CompletedAt == nil {
		return len(w.Creates) == 0 && w.Activation == nil
	}
	return initialHandoverTime(*v.CompletedAt) && !v.CompletedAt.Before(v.ClaimedAt)
}
