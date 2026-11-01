package bootstrap

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
)

// promotedKeyNames are the installation-derived public key and role names
// (ADR-194 decision 3). The phase-3 artifact creates them create-only; the
// continuation reads the signing key and worker roots back afterwards.
func promotedKeyNames(installation, epoch string, p contracts.InstallerOwnerPromotion) (contracts.OwnerPublicTransit, contracts.OwnerPublicSigning, contracts.OwnerPublicWorkerPKI) {
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	return contracts.OwnerPublicTransit{Mount: p.TransitMount, Key: prefix + "-browser-sessions"},
		contracts.OwnerPublicSigning{Mount: p.TransitMount, Name: prefix + "-work-signing"},
		contracts.OwnerPublicWorkerPKI{Mount: p.WorkerPKIMount, Role: prefix + "-download-worker", IssuerEpoch: epoch}
}

// promotedArtifactKeyID is the derived artifact key ID (ADR-194 D8) until the
// regional key-service work installs the local key service.
func promotedArtifactKeyID(installation string) string {
	return "asservat-" + strings.ReplaceAll(installation, "-", "") + "-artifact"
}

// promotedOwnerParts are the producers' results a promoted input is derived
// from. Signing carries the read-back version and public key.
type promotedOwnerParts struct {
	Settings       contracts.InstallerPublicSettings
	Sources        kube.PublicSources
	Qualification  capacityapp.CapacityQualification
	ConnectorRoots [][]byte
	IssuerEpoch    string
	Signing        contracts.OwnerPublicSigning
	WorkerRoots    [][]byte
	Projection     contracts.WorkerObjectReference
	// Downloads are the configured hub-local download workers (ADR-204),
	// or nil: the worker API, its profile source and the path template.
	Downloads *promotedDownloads
	// Processing is the capacity processing source and guard (ADR-210), or
	// nil without a capacity profile.
	Processing *contracts.OwnerPublicEnvironment
}

// derivePromotedOwner adds Native and Public to the selected installed owner
// input (ADR-194 decisions 4-10). Limits are the documented defaults, not
// qualified capacity claims. The result must pass the owner's own validator.
func derivePromotedOwner(in contracts.OwnerDeployment, x promotedOwnerParts, now time.Time) (contracts.OwnerDeployment, error) {
	p, q := x.Settings.Promotion, x.Qualification
	if p == nil || in.ProviderAuthentication == nil || in.Native != nil || in.Public != nil || !q.Valid() || x.Sources.WorkerConfiguration.Source.Name == "" || x.Sources.DownloadEnvironment.Source.Name == "" {
		return in, &fixedStepError{"parts", mounts.ErrUnavailable}
	}
	roots, err := providerconfig.TrustRootsPEM([]byte(p.ProviderRootsPEM), now)
	if err != nil {
		return in, &fixedStepError{"provider-roots", err}
	}
	capture, err := json.Marshal(q.RootBacking.Capture.Policy)
	if err != nil {
		return in, mounts.ErrUnavailable
	}
	if _, err = decodeAuditPolicy(capture, "capture", in.PermissionRootID, in.InstallationID); err != nil {
		return in, &fixedStepError{"capture-policy", err}
	}
	transit, signing, pki := promotedKeyNames(in.InstallationID, x.IssuerEpoch, *p)
	if x.Signing.Mount != signing.Mount || x.Signing.Name != signing.Name || x.Signing.Version < 1 {
		return in, &fixedStepError{"signing", mounts.ErrUnavailable}
	}
	signing.Version, signing.PublicKey = x.Signing.Version, x.Signing.PublicKey
	signing.KeyID = signing.Name + "-v" + strconv.Itoa(signing.Version)
	pki.Roots = x.WorkerRoots
	// One retention for both audited lanes: the shorter never exceeds what
	// either lane prepaid.
	retention := min(q.RootBacking.Normal.RetainedSeconds, q.RootBacking.Resolution.RetainedSeconds)
	out := in
	out.Native = &contracts.OwnerNativeDeployment{ConnectorRoots: x.ConnectorRoots, WorkerAPIs: []contracts.OwnerNativeWorkerAPI{}, RetentionTopologies: []contracts.OwnerNativeTopology{},
		Connections: in.Connections, Concurrency: in.Concurrency}
	out.Public = &contracts.OwnerPublicDeployment{CaptureHistory: x.Settings.CaptureHistory, Format: contracts.OwnerPublicDeploymentFormat, Origin: x.Settings.Origin,
		BrowserRootID: x.Sources.BrowserRootID, BrowserSettings: x.Sources.BrowserSettings, IdentitySettings: x.Sources.IdentitySettings,
		BrowserAudience: p.BrowserAudience, ProviderRoots: roots, SessionTransit: transit,
		ClusterCatalog: x.Sources.ClusterCatalog, WorkSigning: signing, Standby: 2, Captures: 1, PreviewSeconds: 120,
		CaptureAuditPolicy: capture,
		Capacity:           contracts.OwnerPublicCapacity{QualificationID: q.ID, QualificationDigest: hex.EncodeToString(q.Digest[:]), AccountVersion: q.RootBacking.AccountVersion},
		AuditStoreID:       q.RootBacking.Capture.Policy.StoreID, ArtifactKeyID: promotedArtifactKeyID(in.InstallationID),
		WorkerConfiguration: x.Sources.WorkerConfiguration, WorkerPKI: pki,
		DownloadEnvironment: contracts.OwnerPublicEnvironment{Source: x.Sources.DownloadEnvironment.Source, Guard: x.Sources.DownloadEnvironment.Guard, Paths: []contracts.DownloadEnvironmentPath{}},
		DownloadPlan:        contracts.OwnerPublicDownloadPlan{OutputLimit: 16 << 20, ReadLimit: 24 << 20, RequestLimit: 4, DurationSeconds: 300}, // ADR-248: one 8 MiB recording and a resume
		Port:                contracts.OwnerInstalledPublicPort, Version: p.Version,
		OperationConcurrency: 8, MCPPerIdentity: 2, DownloadConcurrency: 4, DownloadsPerIdentity: 2, DownloadMaxSeconds: 3600,
		OperationAudit:    contracts.OwnerPublicOperationAudit{RetentionSeconds: int(retention), NormalConcurrency: 8, ResolutionConcurrency: 2, PerPrincipalConcurrency: 2, NormalPerSecond: 50, ResolutionPerSecond: 10},
		RuntimeProjection: x.Projection, Processing: x.Processing}
	// ADR-237: the delegation envelopes whose previewers may preview
	// permission changes in the browser.
	for _, d := range x.Settings.PermissionDelegations {
		if len(d.Previewers) > 0 {
			out.Public.PermissionDelegations = append(out.Public.PermissionDelegations, d)
		}
	}
	if d := x.Downloads; d != nil {
		// ADR-204 decisions 2 and 4: the one pinned worker API owns the
		// profile source's namespace, and one path template per installation.
		if !reflect.DeepEqual(d.Source, x.Sources.WorkerConfiguration) || d.API.ClusterID != in.ClusterID || d.API.Namespace.UID == in.Namespace.UID {
			return in, &fixedStepError{"downloads", mounts.ErrUnavailable}
		}
		template := d.Template
		out.Native.WorkerAPIs = []contracts.OwnerNativeWorkerAPI{d.API}
		out.Public.DownloadEnvironment.PathTemplate = &template
	}
	// The recipe digest covers the read-back key and roots, so it comes last.
	if _, out.Public.ProviderRecipeSHA256, err = providerconfig.OwnerPublicProviderRecipeFor(out, *in.ProviderAuthentication, now); err != nil {
		return in, &fixedStepError{"recipe", err}
	}
	if err = validateUnprojectedOwnerDeployment(out); err != nil {
		return in, &fixedStepError{"validate", err}
	}
	return out, nil
}
