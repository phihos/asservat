package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

// ReadProcessingReport uses the existing hub credential and processing
// transaction. Each continuation is a new current observation of retained rows.
func (s *ProcessingInventory) ReadProcessingReport(ctx context.Context, a value.ProcessingAuthority, query value.ProcessingReportQuery) (value.ProcessingReportPage, error) {
	var out value.ProcessingReportPage
	query = query.Normalized()
	if s == nil || s.decisions == nil || !query.Valid() {
		return out, value.ErrUnavailable
	}
	digest := hex.EncodeToString(a.Policy.Revision.Digest[:])
	if query.CreatedBefore.IsZero() {
		query.CreatedBefore = a.ObservedAt.UTC()
		query.PolicyDigest = digest
	}
	if query.CreatedBefore.After(a.ObservedAt) || query.PolicyDigest != digest {
		return out, value.ErrUnavailable
	}
	err := s.decisions.transaction(ctx, a, func(call context.Context, q *custodydb.Queries, root custodydb.ProcessingRoot, now time.Time) error {
		if !root.InitializedAt.Valid {
			return value.ErrUnavailable
		}
		out = value.ProcessingReportPage{
			SchemaVersion: value.ProcessingReportFormat, RootID: uid(root.RootID), InstallationID: uid(root.InstallationID),
			Section: query.Section, SelectionCreatedBefore: query.CreatedBefore.UTC(),
			PolicyRevision: value.ProcessingReportRevision{UID: a.Policy.Revision.UID, Generation: a.Policy.Revision.Generation, Digest: digest},
			Records:        []value.ProcessingReportRecord{}, ObservedAt: a.ObservedAt.UTC(),
			ValidUntil:            identity.Earlier(a.ValidUntil, root.ValidUntil.Time).UTC(),
			ProcessorDeclarations: "supplied", Coverage: value.ProcessingReportCoverage(),
		}
		if a.Policy.Processors == nil {
			out.ProcessorDeclarations = "unsupplied"
		}
		records, err := processingReportRecords(call, q, a, query, now)
		if err != nil || len(records) > query.Limit+1 {
			return value.ErrUnavailable
		}
		more := len(records) > query.Limit
		if more {
			records = records[:query.Limit]
		}
		out.Records = records
		for _, record := range records {
			out.ValidUntil = identity.Earlier(out.ValidUntil, record.VisibleUntil).UTC()
		}
		next := query
		if more {
			next.After = records[len(records)-1].Cursor()
			out.Next = &next
		} else {
			sections := []string{"artifacts", "shares", "downloads", "operations", "rules", "paths", "processors"}
			index := slices.Index(sections, query.Section)
			if index+1 < len(sections) {
				next.Section = sections[index+1]
				next.After = value.ProcessingReportCursor{}
				out.Next = &next
			}
		}
		if !out.Valid(query, now) {
			return value.ErrUnavailable
		}
		return nil
	})
	if err != nil || ctx.Err() != nil || !out.Valid(query, time.Now()) {
		return value.ProcessingReportPage{}, value.ErrUnavailable
	}
	return out, nil
}

func processingReportRecords(ctx context.Context, q *custodydb.Queries, a value.ProcessingAuthority, query value.ProcessingReportQuery, now time.Time) ([]value.ProcessingReportRecord, error) {
	after := query.After
	if after.ID == "" {
		after.ID = "00000000-0000-0000-0000-000000000000"
	}
	limit := int32(query.Limit + 1)
	records := []value.ProcessingReportRecord{}
	switch query.Section {
	case "artifacts":
		if after.ClusterID == "" {
			after.ClusterID, after.AttemptID = after.ID, after.ID
		}
		rows, err := q.ReportProcessingArtifacts(ctx, custodydb.ReportProcessingArtifactsParams{
			RootID: id(a.Policy.RootID), ObservedAt: ts(now), CreatedBefore: ts(query.CreatedBefore),
			AfterClusterID: id(after.ClusterID), AfterID: id(after.ID), AfterAttemptID: id(after.AttemptID), PageLimit: limit,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			record, err := processingReportArtifact(row, now)
			if err != nil {
				return nil, err
			}
			records = append(records, record)
		}
	case "shares":
		if after.CreatedAt.IsZero() {
			after.CreatedAt = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		rows, err := q.ReportProcessingShares(ctx, custodydb.ReportProcessingSharesParams{
			RootID: id(a.Policy.RootID), ObservedAt: ts(now), CreatedBefore: ts(query.CreatedBefore), AfterCreatedAt: ts(after.CreatedAt),
			AfterID: id(after.ID), AfterOrdinal: after.Ordinal, PageLimit: limit,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			var recipient shareRecipientWire
			if json.Unmarshal(row.Recipient, &recipient) != nil {
				return nil, value.ErrUnavailable
			}
			v := value.ProcessingReportShare{
				ShareID: uid(row.ID), ArtifactID: uid(row.ArtifactID), RecipientKind: recipient.Kind, RecipientIssuer: recipient.Issuer,
				RecipientID: recipient.ID, Ordinal: row.Ordinal, CreatedAt: row.CreatedAt.Time.UTC(), ExpiresAt: row.ExpiresAt.Time.UTC(), State: "recorded",
			}
			if !now.Before(v.ExpiresAt) {
				v.State = "expired"
			}
			if row.RevokedAt.Valid {
				at := row.RevokedAt.Time.UTC()
				v.RevokedAt, v.State = &at, "revoked"
			}
			records = append(records, value.ProcessingReportRecord{VisibleUntil: row.RetireBy.Time.UTC(), Share: &v})
		}
	case "downloads":
		rows, err := q.ReportProcessingDownloads(ctx, custodydb.ReportProcessingDownloadsParams{
			RootID: id(a.Policy.RootID), AfterID: id(after.ID), CreatedBefore: ts(query.CreatedBefore), ObservedAt: ts(now), PageLimit: limit,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			var principal identity.Principal
			if json.Unmarshal(row.Principal, &principal) != nil {
				return nil, value.ErrUnavailable
			}
			v := value.ProcessingReportDownload{
				DownloadID: uid(row.ID), ArtifactID: uid(row.ArtifactID), Issuer: principal.Issuer, Subject: principal.Subject, ClientID: principal.ClientID, PrincipalKind: principal.Kind,
				State: artifact.DownloadState(row.State), CreatedAt: row.CreatedAt.Time.UTC(), Deadline: row.Deadline.Time.UTC(), EmittedBytes: row.EmittedBytes, ClientReceipt: "unknown",
			}
			records = append(records, value.ProcessingReportRecord{VisibleUntil: row.VisibleUntil.Time.UTC(), Download: &v})
		}
	case "operations":
		rows, err := q.ReportProcessingOperations(ctx, custodydb.ReportProcessingOperationsParams{
			RootID: id(a.Policy.RootID), CreatedBefore: ts(query.CreatedBefore), ObservedAt: ts(now), AfterID: id(after.ID), AfterOrdinal: after.Ordinal, PageLimit: limit,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			var principal identity.Principal
			if json.Unmarshal(row.Actor, &principal) != nil {
				return nil, value.ErrUnavailable
			}
			v := value.ProcessingReportOperation{
				OperationID: uid(row.ID), ArtifactID: row.ArtifactID, Ordinal: row.Ordinal, Name: row.OperationName, Lane: row.Lane,
				Issuer: principal.Issuer, Subject: principal.Subject, ClientID: principal.ClientID, PrincipalKind: principal.Kind, CreatedAt: row.CreatedAt.Time.UTC(),
				IntentAcknowledged: row.IntentAcknowledged, OutcomeAcknowledged: row.OutcomeAcknowledged, Status: row.Status, ClientReceipt: "unknown",
			}
			if row.OutputBytes >= 0 {
				count := row.OutputBytes
				v.OutputBytes = &count
			}
			records = append(records, value.ProcessingReportRecord{VisibleUntil: row.VisibleUntil.Time.UTC(), Operation: &v})
		}
	case "rules":
		rows, err := q.ReportProcessingRules(ctx, custodydb.ReportProcessingRulesParams{
			RootID: id(a.Policy.RootID), AfterID: id(after.ID), ObservedAt: ts(now), CreatedBefore: ts(query.CreatedBefore), PageLimit: limit,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			v := value.ProcessingReportRule{ID: uid(row.ID), Revision: row.Revision, State: row.State, AdministrationUntil: row.ValidUntil.Time.UTC(), RetireBy: row.RetireBy.Time.UTC()}
			var scope value.ProcessingScope
			if json.Unmarshal(row.Scope, &scope) != nil {
				return nil, value.ErrUnavailable
			}
			v.Scope = value.ProcessingReportScopeFrom(scope)
			if row.CreatedAt.Valid {
				at := row.CreatedAt.Time.UTC()
				v.CreatedAt = &at
			}
			records = append(records, value.ProcessingReportRecord{VisibleUntil: row.RetireBy.Time.UTC(), Rule: &v})
		}
	case "paths":
		paths := slices.Clone(a.Policy.Paths)
		slices.SortFunc(paths, func(x, y artifact.DownloadPath) int { return strings.Compare(x.ID, y.ID) })
		for _, path := range paths {
			if path.ID <= query.After.ID {
				continue
			}
			v := value.ProcessingReportPath{ID: path.ID, TargetClusterID: path.TargetClusterID, StoreID: path.StoreID, StorageRegion: path.StorageRegion,
				AcquisitionClusterID: path.AcquisitionClusterID, AcquisitionRegion: path.AcquisitionRegion, ConnectorClusterID: path.ConnectorClusterID,
				ConnectorRegion: path.ConnectorRegion, HubClusterID: path.HubClusterID, HubRegion: path.HubRegion}
			records = append(records, value.ProcessingReportRecord{VisibleUntil: a.ValidUntil.UTC(), Path: &v})
			if len(records) == int(limit) {
				break
			}
		}
	case "processors":
		organizations := slices.Clone(a.Policy.Processors)
		slices.SortFunc(organizations, func(x, y value.ProcessingOrganization) int { return strings.Compare(x.ID, y.ID) })
		for _, organization := range organizations {
			if organization.ID <= query.After.ID {
				continue
			}
			v := organization
			v.Activities, v.Regions = slices.Clone(organization.Activities), slices.Clone(organization.Regions)
			records = append(records, value.ProcessingReportRecord{VisibleUntil: a.ValidUntil.UTC(), Processor: &v})
			if len(records) == int(limit) {
				break
			}
		}
	default:
		return nil, value.ErrUnavailable
	}
	return records, nil
}

func processingReportArtifact(row custodydb.ReportProcessingArtifactsRow, now time.Time) (value.ProcessingReportRecord, error) {
	var parents []artifact.Location
	if json.Unmarshal(row.Parents, &parents) != nil {
		return value.ProcessingReportRecord{}, value.ErrUnavailable
	}
	native := row.NativeType
	if native == artifact.PodStatusArtifact {
		if row.ActionID != "pod-status" || row.DataClass != "metadata" {
			return value.ProcessingReportRecord{}, value.ErrUnavailable
		}
		native = "podStatus"
	}
	name := native
	if name == "podStatus" {
		name = artifact.PodStatusArtifact
	}
	typ, ok := artifact.LookupNativeType(name)
	if !ok || !typ.AllowsClass(row.DataClass) {
		return value.ProcessingReportRecord{}, value.ErrUnavailable
	}
	v := value.ProcessingReportArtifact{
		ArtifactID: uid(row.ArtifactID), CaptureID: uid(row.CaptureID), CaseID: uid(row.CaseID), ClusterID: uid(row.ClusterID), AttemptID: uid(row.AttemptID),
		NamespaceUID: row.NamespaceUid, WorkloadUID: row.WorkloadUid, StoreID: row.StoreID, PurposeRef: row.PurposeRef, NativeType: native, DataClass: row.DataClass,
		PrivacyClass: "potentialPersonalData", Origin: row.Origin, Parents: []string{}, AnchorAt: row.AnchorAt.Time.UTC(), OriginalExpiresAt: row.OriginalExpiresAt.Time.UTC(),
		OriginalDeleteBy: row.OriginalDeleteBy.Time.UTC(), ExpiresAt: row.EffectiveExpiresAt.Time.UTC(), DeleteBy: row.EffectiveDeleteBy.Time.UTC(),
		CustodyState: row.State, DeletionState: "retained",
	}
	for _, parent := range parents {
		if parent.Validate() != nil || parent.ArtifactID == v.ArtifactID {
			return value.ProcessingReportRecord{}, value.ErrUnavailable
		}
		v.Parents = append(v.Parents, parent.ArtifactID)
	}
	if !now.Before(v.ExpiresAt) {
		v.DeletionState = "pending"
	}
	if !now.Before(v.DeleteBy) {
		v.DeletionState = "overdue"
	}
	if row.DeletedAt.Valid {
		at := row.DeletedAt.Time.UTC()
		v.DeletedAt, v.DeletionState = &at, "deleted"
	}
	record := value.ProcessingReportRecord{VisibleUntil: row.RetireBy.Time.UTC(), Artifact: &v}
	if !record.Valid("artifacts", now) || !authorization.UUID(v.StoreID) {
		return value.ProcessingReportRecord{}, value.ErrUnavailable
	}
	return record, nil
}
