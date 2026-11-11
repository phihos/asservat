package privacy

import (
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const ProcessingReportLimit = 3
const ProcessingReportFormat = "processing-report/v1"

var processingReportSections = []string{"artifacts", "shares", "downloads", "operations", "rules", "paths", "processors"}

type ProcessingReportCursor struct {
	ID        string    `json:"id,omitempty"`
	ClusterID string    `json:"cluster_id,omitempty"`
	AttemptID string    `json:"attempt_id,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	Ordinal   int64     `json:"ordinal,omitempty"`
}

type ProcessingReportQuery struct {
	Section       string                 `json:"section"`
	Limit         int                    `json:"limit"`
	CreatedBefore time.Time              `json:"created_before,omitzero"`
	PolicyDigest  string                 `json:"policy_digest,omitempty"`
	After         ProcessingReportCursor `json:"after,omitzero"`
}

func (q ProcessingReportQuery) Normalized() ProcessingReportQuery {
	if q.Section == "" {
		q.Section = "artifacts"
	}
	if q.Limit == 0 {
		q.Limit = ProcessingReportLimit
	}
	return q
}

func reportDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, digit := range s {
		if !strings.ContainsRune("0123456789abcdef", digit) {
			return false
		}
	}
	return true
}

func (q ProcessingReportQuery) Valid() bool {
	q = q.Normalized()
	if !slices.Contains(processingReportSections, q.Section) || q.Limit < 1 || q.Limit > ProcessingReportLimit ||
		q.CreatedBefore.IsZero() != (q.PolicyDigest == "") ||
		!q.CreatedBefore.IsZero() && (q.CreatedBefore.Nanosecond()%1000 != 0 || !reportDigest(q.PolicyDigest)) {
		return false
	}
	c := q.After
	if c == (ProcessingReportCursor{}) {
		return true
	}
	if q.CreatedBefore.IsZero() || c.ID == "" {
		return false
	}
	switch q.Section {
	case "artifacts":
		return authorization.UUID(c.ID) && authorization.UUID(c.ClusterID) && authorization.UUID(c.AttemptID) && c.CreatedAt.IsZero() && c.Ordinal == 0
	case "shares":
		return authorization.UUID(c.ID) && c.ClusterID == "" && c.AttemptID == "" && !c.CreatedAt.IsZero() && !c.CreatedAt.After(q.CreatedBefore) && c.CreatedAt.Nanosecond()%1000 == 0 && c.Ordinal >= 1 && c.Ordinal <= 8
	case "operations":
		return authorization.UUID(c.ID) && c.ClusterID == "" && c.AttemptID == "" && c.CreatedAt.IsZero() && c.Ordinal >= 0 && c.Ordinal <= 100
	case "processors":
		return identity.Text(c.ID, 64) && c.ClusterID == "" && c.AttemptID == "" && c.CreatedAt.IsZero() && c.Ordinal == 0
	default:
		return authorization.UUID(c.ID) && c.ClusterID == "" && c.AttemptID == "" && c.CreatedAt.IsZero() && c.Ordinal == 0
	}
}

type ProcessingReportRevision struct {
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
	Digest     string `json:"digest"`
}

type ProcessingReportArtifact struct {
	ArtifactID        string     `json:"artifact_id"`
	CaptureID         string     `json:"capture_id"`
	CaseID            string     `json:"case_id"`
	ClusterID         string     `json:"cluster_id"`
	AttemptID         string     `json:"attempt_id"`
	NamespaceUID      string     `json:"namespace_uid"`
	WorkloadUID       string     `json:"workload_uid"`
	StoreID           string     `json:"store_id"`
	PurposeRef        string     `json:"purpose_ref"`
	NativeType        string     `json:"native_type"`
	DataClass         string     `json:"data_class"`
	PrivacyClass      string     `json:"privacy_class"`
	Origin            string     `json:"origin"`
	Parents           []string   `json:"parents"`
	AnchorAt          time.Time  `json:"anchor_at"`
	OriginalExpiresAt time.Time  `json:"original_expires_at"`
	OriginalDeleteBy  time.Time  `json:"original_delete_by"`
	ExpiresAt         time.Time  `json:"expires_at"`
	DeleteBy          time.Time  `json:"delete_by"`
	CustodyState      string     `json:"custody_state"`
	DeletedAt         *time.Time `json:"deleted_at,omitempty"`
	DeletionState     string     `json:"deletion_state"`
}

type ProcessingReportShare struct {
	ShareID         string     `json:"share_id"`
	ArtifactID      string     `json:"artifact_id"`
	RecipientKind   string     `json:"recipient_kind"`
	RecipientIssuer string     `json:"recipient_issuer"`
	RecipientID     string     `json:"recipient_id"`
	Ordinal         int64      `json:"ordinal"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	State           string     `json:"state"`
}

type ProcessingReportDownload struct {
	DownloadID    string                 `json:"download_id"`
	ArtifactID    string                 `json:"artifact_id"`
	Issuer        string                 `json:"issuer"`
	Subject       string                 `json:"subject"`
	ClientID      string                 `json:"client_id"`
	PrincipalKind identity.Kind          `json:"principal_kind"`
	State         artifact.DownloadState `json:"state"`
	CreatedAt     time.Time              `json:"created_at"`
	Deadline      time.Time              `json:"deadline"`
	EmittedBytes  int64                  `json:"emitted_bytes"`
	ClientReceipt string                 `json:"client_receipt"`
}

type ProcessingReportOperation struct {
	Lane                string        `json:"lane"`
	OperationID         string        `json:"operation_id"`
	ArtifactID          string        `json:"artifact_id,omitempty"`
	Ordinal             int64         `json:"ordinal"`
	Name                string        `json:"name"`
	Issuer              string        `json:"issuer"`
	Subject             string        `json:"subject"`
	ClientID            string        `json:"client_id"`
	PrincipalKind       identity.Kind `json:"principal_kind"`
	CreatedAt           time.Time     `json:"created_at"`
	IntentAcknowledged  bool          `json:"intent_acknowledged"`
	OutcomeAcknowledged bool          `json:"outcome_acknowledged"`
	Status              string        `json:"status"`
	OutputBytes         *int64        `json:"output_bytes,omitempty"`
	ClientReceipt       string        `json:"client_receipt"`
}

// ProcessingReportScope is a report DTO. The immutable processing scope keeps
// its established stored representation and digest.
type ProcessingReportLocation struct {
	ClusterID  string `json:"cluster_id"`
	ArtifactID string `json:"artifact_id"`
	AttemptID  string `json:"attempt_id"`
}
type ProcessingReportScope struct {
	Kind          string                    `json:"kind"`
	Location      *ProcessingReportLocation `json:"location,omitempty"`
	ClusterID     string                    `json:"cluster_id,omitempty"`
	NamespaceUID  string                    `json:"namespace_uid,omitempty"`
	WorkloadUID   string                    `json:"workload_uid,omitempty"`
	AcquiredFrom  time.Time                 `json:"acquired_from,omitzero"`
	AcquiredUntil time.Time                 `json:"acquired_until,omitzero"`
}

func ProcessingReportScopeFrom(scope ProcessingScope) ProcessingReportScope {
	out := ProcessingReportScope{Kind: scope.Kind, ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID,
		AcquiredFrom: scope.AcquiredFrom.UTC(), AcquiredUntil: scope.AcquiredUntil.UTC()}
	if scope.Kind == "artifact" {
		out.Location = &ProcessingReportLocation{ClusterID: scope.Location.ClusterID, ArtifactID: scope.Location.ArtifactID, AttemptID: scope.Location.AttemptID}
	}
	return out
}
func (s ProcessingReportScope) Domain() ProcessingScope {
	out := ProcessingScope{Kind: s.Kind, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, AcquiredFrom: s.AcquiredFrom, AcquiredUntil: s.AcquiredUntil}
	if s.Location != nil {
		out.Location = artifact.Location{ClusterID: s.Location.ClusterID, ArtifactID: s.Location.ArtifactID, AttemptID: s.Location.AttemptID}
	}
	return out
}

type ProcessingReportRule struct {
	CreatedAt           *time.Time            `json:"created_at,omitempty"`
	ID                  string                `json:"id"`
	Revision            int64                 `json:"revision"`
	State               string                `json:"state"`
	Scope               ProcessingReportScope `json:"scope"`
	AdministrationUntil time.Time             `json:"administration_until"`
	RetireBy            time.Time             `json:"retire_by"`
}

type ProcessingReportPath struct {
	ID                   string `json:"id"`
	TargetClusterID      string `json:"target_cluster_id"`
	StoreID              string `json:"store_id"`
	StorageRegion        string `json:"storage_region"`
	AcquisitionClusterID string `json:"acquisition_cluster_id"`
	AcquisitionRegion    string `json:"acquisition_region"`
	ConnectorClusterID   string `json:"connector_cluster_id"`
	ConnectorRegion      string `json:"connector_region"`
	HubClusterID         string `json:"hub_cluster_id"`
	HubRegion            string `json:"hub_region"`
}

// Exactly one typed record is present. VisibleUntil is the original source
// control cutoff, narrowed further by the enclosing page's current authority.
type ProcessingReportRecord struct {
	VisibleUntil time.Time                  `json:"visible_until"`
	Artifact     *ProcessingReportArtifact  `json:"artifact,omitempty"`
	Share        *ProcessingReportShare     `json:"share,omitempty"`
	Download     *ProcessingReportDownload  `json:"download,omitempty"`
	Operation    *ProcessingReportOperation `json:"operation,omitempty"`
	Rule         *ProcessingReportRule      `json:"rule,omitempty"`
	Path         *ProcessingReportPath      `json:"path,omitempty"`
	Processor    *ProcessingOrganization    `json:"processor,omitempty"`
}

type ProcessingReportPage struct {
	SchemaVersion          string                   `json:"schema_version"`
	RootID                 string                   `json:"root_id"`
	InstallationID         string                   `json:"installation_id"`
	Section                string                   `json:"section"`
	SelectionCreatedBefore time.Time                `json:"selection_created_before"`
	PolicyRevision         ProcessingReportRevision `json:"policy_revision"`
	Records                []ProcessingReportRecord `json:"records"`
	Next                   *ProcessingReportQuery   `json:"next,omitempty"`
	ObservedAt             time.Time                `json:"observed_at"`
	ValidUntil             time.Time                `json:"valid_until"`
	ProcessorDeclarations  string                   `json:"processor_declarations"`
	Coverage               []string                 `json:"coverage"`
}

func ProcessingReportCoverage() []string {
	return []string{"retained metadata observations", "unknown client receipt", "legal exceptions disabled", "recorded lineage"}
}

func (p ProcessingReportPage) Valid(q ProcessingReportQuery, now time.Time) bool {
	q = q.Normalized()
	if !q.Valid() || p.SchemaVersion != ProcessingReportFormat || !authorization.UUID(p.RootID) || !authorization.UUID(p.InstallationID) ||
		p.Section != q.Section || p.SelectionCreatedBefore.IsZero() || p.SelectionCreatedBefore.After(p.ObservedAt) ||
		p.SelectionCreatedBefore.Nanosecond()%1000 != 0 || q.PolicyDigest != "" && q.PolicyDigest != p.PolicyRevision.Digest ||
		!q.CreatedBefore.IsZero() && !q.CreatedBefore.Equal(p.SelectionCreatedBefore) ||
		!identity.Text(p.PolicyRevision.UID, 64) || p.PolicyRevision.Generation < 1 || !reportDigest(p.PolicyRevision.Digest) ||
		!identity.Fresh(p.ObservedAt, p.ValidUntil, now, identity.SQLFenced.Interval()) || p.Records == nil || len(p.Records) > q.Limit ||
		!slices.Contains([]string{"supplied", "unsupplied"}, p.ProcessorDeclarations) || !slices.Equal(p.Coverage, ProcessingReportCoverage()) {
		return false
	}
	last := q.After
	for _, record := range p.Records {
		if !record.Valid(q.Section, now) || p.ValidUntil.After(record.VisibleUntil) {
			return false
		}
		var created time.Time
		switch {
		case record.Share != nil:
			created = record.Share.CreatedAt
		case record.Download != nil:
			created = record.Download.CreatedAt
		case record.Operation != nil:
			created = record.Operation.CreatedAt
		case record.Rule != nil && record.Rule.CreatedAt != nil:
			created = *record.Rule.CreatedAt
		}
		if created.After(p.SelectionCreatedBefore) {
			return false
		}
		cursor := record.Cursor()
		if !reportCursorAfter(q.Section, cursor, last) {
			return false
		}
		last = cursor
	}
	if p.Next == nil {
		return q.Section == "processors"
	}
	next := *p.Next
	if !next.Valid() || next.Limit != q.Limit || next.PolicyDigest != p.PolicyRevision.Digest || !next.CreatedBefore.Equal(p.SelectionCreatedBefore) {
		return false
	}
	if next.Section == q.Section {
		return len(p.Records) == q.Limit && next.After == last
	}
	index := slices.Index(processingReportSections, q.Section)
	return index+1 < len(processingReportSections) && next.Section == processingReportSections[index+1] && next.After == (ProcessingReportCursor{})
}

func reportCursorAfter(section string, a, b ProcessingReportCursor) bool {
	switch section {
	case "artifacts":
		if a.ClusterID != b.ClusterID {
			return a.ClusterID > b.ClusterID
		}
		if a.ID != b.ID {
			return a.ID > b.ID
		}
		return a.AttemptID > b.AttemptID
	case "shares":
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.After(b.CreatedAt)
		}
	}
	if a.ID != b.ID {
		return a.ID > b.ID
	}
	return a.Ordinal > b.Ordinal
}

func (r ProcessingReportRecord) Cursor() ProcessingReportCursor {
	switch {
	case r.Artifact != nil:
		return ProcessingReportCursor{ID: r.Artifact.ArtifactID, ClusterID: r.Artifact.ClusterID, AttemptID: r.Artifact.AttemptID}
	case r.Share != nil:
		return ProcessingReportCursor{ID: r.Share.ShareID, CreatedAt: r.Share.CreatedAt, Ordinal: r.Share.Ordinal}
	case r.Download != nil:
		return ProcessingReportCursor{ID: r.Download.DownloadID}
	case r.Operation != nil:
		return ProcessingReportCursor{ID: r.Operation.OperationID, Ordinal: r.Operation.Ordinal}
	case r.Rule != nil:
		return ProcessingReportCursor{ID: r.Rule.ID}
	case r.Path != nil:
		return ProcessingReportCursor{ID: r.Path.ID}
	case r.Processor != nil:
		return ProcessingReportCursor{ID: r.Processor.ID}
	}
	return ProcessingReportCursor{}
}

func (r ProcessingReportRecord) Valid(section string, now time.Time) bool {
	count := 0
	for _, present := range []bool{r.Artifact != nil, r.Share != nil, r.Download != nil, r.Operation != nil, r.Rule != nil, r.Path != nil, r.Processor != nil} {
		if present {
			count++
		}
	}
	if count != 1 || !now.Before(r.VisibleUntil) {
		return false
	}
	switch section {
	case "artifacts":
		v := r.Artifact
		if v == nil {
			return false
		}
		name := v.NativeType
		if name == "podStatus" {
			name = artifact.PodStatusArtifact
		}
		typ, known := artifact.LookupNativeType(name)
		if !known || !typ.AllowsClass(v.DataClass) {
			return false
		}
		seen := map[string]bool{v.ArtifactID: true}
		for _, parent := range v.Parents {
			if !authorization.UUID(parent) || seen[parent] {
				return false
			}
			seen[parent] = true
		}
		return v != nil && authorization.UUID(v.ArtifactID) && authorization.UUID(v.CaptureID) && authorization.UUID(v.CaseID) &&
			authorization.UUID(v.ClusterID) && authorization.UUID(v.AttemptID) && authorization.UUID(v.StoreID) &&
			identity.Text(v.NamespaceUID, 64) && identity.Text(v.WorkloadUID, 64) && identity.Text(v.PurposeRef, 128) &&
			v.PrivacyClass == "potentialPersonalData" && v.Parents != nil && len(v.Parents) <= MaxProcessingParents &&
			(v.Origin == "capture" && len(v.Parents) == 0 || v.Origin == "derived" && len(v.Parents) > 0) &&
			!v.AnchorAt.IsZero() && v.OriginalExpiresAt.After(v.AnchorAt) && v.OriginalDeleteBy.After(v.OriginalExpiresAt) &&
			!v.ExpiresAt.Before(v.AnchorAt) && !v.ExpiresAt.After(v.OriginalExpiresAt) && !v.DeleteBy.Before(v.ExpiresAt) &&
			!v.DeleteBy.After(v.OriginalDeleteBy) &&
			slices.Contains([]string{"stored_unpublished", "deleting", "deleted"}, v.CustodyState) &&
			(v.CustodyState == "deleted") == (v.DeletedAt != nil) && (v.DeletedAt == nil || !v.DeletedAt.After(now)) &&
			slices.Contains([]string{"retained", "pending", "overdue", "deleted"}, v.DeletionState)
	case "shares":
		v := r.Share
		return v != nil && authorization.UUID(v.ShareID) && authorization.UUID(v.ArtifactID) &&
			(authorization.ShareRecipient{Kind: v.RecipientKind, Issuer: v.RecipientIssuer, ID: v.RecipientID}).Valid() &&
			v.Ordinal >= 1 && v.Ordinal <= 8 && !v.CreatedAt.IsZero() && v.ExpiresAt.After(v.CreatedAt) && slices.Contains([]string{"recorded", "expired", "revoked"}, v.State)
	case "downloads":
		v := r.Download
		return v != nil && authorization.UUID(v.DownloadID) && authorization.UUID(v.ArtifactID) &&
			(identity.Principal{Issuer: v.Issuer, Subject: v.Subject, ClientID: v.ClientID, Kind: v.PrincipalKind}).Valid() &&
			v.State.Valid() && !v.CreatedAt.IsZero() && v.Deadline.After(v.CreatedAt) && v.EmittedBytes >= 0 && v.ClientReceipt == "unknown"
	case "operations":
		v := r.Operation
		return v != nil && authorization.UUID(v.OperationID) && (v.Ordinal == 0 && v.ArtifactID == "" || v.Ordinal >= 1 && v.Ordinal <= 100 && authorization.UUID(v.ArtifactID)) &&
			slices.Contains([]string{"normal", "resolution", "processing"}, v.Lane) && identity.Text(v.Name, 64) && v.Name != "get_processing_report" &&
			(identity.Principal{Issuer: v.Issuer, Subject: v.Subject, ClientID: v.ClientID, Kind: v.PrincipalKind}).Valid() &&
			!v.CreatedAt.IsZero() && (v.OutputBytes == nil || *v.OutputBytes >= 0) && (!v.OutcomeAcknowledged || v.IntentAcknowledged && v.OutputBytes != nil) &&
			slices.Contains([]string{"unknown", "success", "denied", "invalid", "unavailable", "interrupted"}, v.Status) && v.ClientReceipt == "unknown"
	case "rules":
		v := r.Rule
		return v != nil && (ProcessingInventoryRule{ID: v.ID, Revision: v.Revision, State: v.State, Scope: v.Scope.Domain(), AdministrationUntil: v.AdministrationUntil, RetireBy: v.RetireBy}).Valid()
	case "paths":
		v := r.Path
		return v != nil && authorization.UUID(v.ID) && authorization.UUID(v.TargetClusterID) && authorization.UUID(v.StoreID) &&
			authorization.UUID(v.AcquisitionClusterID) && authorization.UUID(v.ConnectorClusterID) && authorization.UUID(v.HubClusterID) &&
			identity.Text(v.StorageRegion, 63) && identity.Text(v.AcquisitionRegion, 63) && identity.Text(v.ConnectorRegion, 63) && identity.Text(v.HubRegion, 63)
	case "processors":
		return r.Processor != nil && ProcessingOrganizationsValid([]ProcessingOrganization{*r.Processor})
	}
	return false
}
