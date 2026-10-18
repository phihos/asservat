package kubernetes

import (
	"context"
	"errors"
)

// OwnerIdentityReadCheck is a closed diagnostic vocabulary, not an authority.
type OwnerIdentityReadCheck uint8

const (
	ownerReadUnspecified OwnerIdentityReadCheck = iota
	ownerReadInput
	ownerReadInitialGuard
	ownerReadTokenRead
	ownerReadInitialTokenReview
	ownerReadTokenInterval
	ownerReadInitialJournal
	ownerReadProjections
	ownerReadInitialDeployment
	ownerReadInitialPod
	ownerReadFinalTokenReview
	ownerReadFinalPod
	ownerReadFinalDeployment
	ownerReadFinalJournal
	ownerReadFinalGuard
	ownerReadFinalDeadline
	ownerReadJournalRead
	ownerReadJournalMetadata
	ownerReadJournalState
	ownerReadJournalReceipts
	ownerReadJournalOriginalPins
	ownerReadJournalChildNames
	ownerReadProjectionReceipt
	ownerReadConfigurationRead
	ownerReadConfigurationMetadata
	ownerReadConfigurationContent
	ownerReadConfigurationDigest
	ownerReadCredentialsRead
	ownerReadCredentialsMetadata
	ownerReadCredentialsContent
	ownerReadCredentialsManifest
	ownerReadLaunchReceipt
	ownerReadDeploymentRead
	ownerReadDeploymentMetadata
	ownerReadDeploymentRevision
	ownerReadDeploymentAnnotations
	ownerReadDeploymentRunningDigest
	ownerReadDeploymentInertDigest
	ownerReadDeploymentProviderBinding
	ownerReadDeploymentTemplateDigest
	ownerReadDeploymentTemplate
	ownerReadAccountRead
	ownerReadAccountContent
	ownerReadFinalPodChanged
	ownerReadLiveDigest
	ownerReadLiveNamespaceRead
	ownerReadLiveNamespaceContent
	ownerReadLiveAccountRead
	ownerReadLiveAccountContent
	ownerReadLiveDeploymentRead
	ownerReadLiveDeploymentContent
	ownerReadLivePodRead
	ownerReadLivePodContent
	ownerReadLiveReplicaRead
	ownerReadLiveReplicaContent
)

func (v OwnerIdentityReadCheck) String() string {
	switch v {
	case ownerReadUnspecified:
		return "unspecified"
	case ownerReadInput:
		return "input"
	case ownerReadInitialGuard:
		return "initial-guard"
	case ownerReadTokenRead:
		return "token-read"
	case ownerReadInitialTokenReview:
		return "initial-token-review"
	case ownerReadTokenInterval:
		return "token-interval"
	case ownerReadInitialJournal:
		return "initial-journal"
	case ownerReadProjections:
		return "projections"
	case ownerReadInitialDeployment:
		return "initial-deployment"
	case ownerReadInitialPod:
		return "initial-pod"
	case ownerReadFinalTokenReview:
		return "final-token-review"
	case ownerReadFinalPod:
		return "final-pod"
	case ownerReadFinalDeployment:
		return "final-deployment"
	case ownerReadFinalJournal:
		return "final-journal"
	case ownerReadFinalGuard:
		return "final-guard"
	case ownerReadFinalDeadline:
		return "final-deadline"
	case ownerReadJournalRead:
		return "journal-read"
	case ownerReadJournalMetadata:
		return "journal-metadata"
	case ownerReadJournalState:
		return "journal-state"
	case ownerReadJournalReceipts:
		return "journal-receipts"
	case ownerReadJournalOriginalPins:
		return "journal-original-pins"
	case ownerReadJournalChildNames:
		return "journal-child-names"
	case ownerReadProjectionReceipt:
		return "projection-receipt"
	case ownerReadConfigurationRead:
		return "configuration-read"
	case ownerReadConfigurationMetadata:
		return "configuration-metadata"
	case ownerReadConfigurationContent:
		return "configuration-content"
	case ownerReadConfigurationDigest:
		return "configuration-digest"
	case ownerReadCredentialsRead:
		return "credentials-read"
	case ownerReadCredentialsMetadata:
		return "credentials-metadata"
	case ownerReadCredentialsContent:
		return "credentials-content"
	case ownerReadCredentialsManifest:
		return "credentials-manifest"
	case ownerReadLaunchReceipt:
		return "launch-receipt"
	case ownerReadDeploymentRead:
		return "deployment-read"
	case ownerReadDeploymentMetadata:
		return "deployment-metadata"
	case ownerReadDeploymentRevision:
		return "deployment-revision"
	case ownerReadDeploymentAnnotations:
		return "deployment-annotations"
	case ownerReadDeploymentRunningDigest:
		return "deployment-running-digest"
	case ownerReadDeploymentInertDigest:
		return "deployment-inert-digest"
	case ownerReadDeploymentProviderBinding:
		return "deployment-provider-binding"
	case ownerReadDeploymentTemplateDigest:
		return "deployment-template-digest"
	case ownerReadDeploymentTemplate:
		return "deployment-template"
	case ownerReadAccountRead:
		return "account-read"
	case ownerReadAccountContent:
		return "account-content"
	case ownerReadFinalPodChanged:
		return "final-pod-changed"
	case ownerReadLiveDigest:
		return "live-digest"
	case ownerReadLiveNamespaceRead:
		return "live-namespace-read"
	case ownerReadLiveNamespaceContent:
		return "live-namespace-content"
	case ownerReadLiveAccountRead:
		return "live-account-read"
	case ownerReadLiveAccountContent:
		return "live-account-content"
	case ownerReadLiveDeploymentRead:
		return "live-deployment-read"
	case ownerReadLiveDeploymentContent:
		return "live-deployment-content"
	case ownerReadLivePodRead:
		return "live-pod-read"
	case ownerReadLivePodContent:
		return "live-pod-content"
	case ownerReadLiveReplicaRead:
		return "live-replica-read"
	case ownerReadLiveReplicaContent:
		return "live-replica-content"
	default:
		return "unspecified"
	}
}

// OwnerIdentityReadFailure retains the original error chain for internal
// errors.Is checks. Error renders only fixed check names, never its causes.
type OwnerIdentityReadFailure struct {
	check OwnerIdentityReadCheck
	cause error
}

func (e *OwnerIdentityReadFailure) Check() OwnerIdentityReadCheck {
	if e == nil {
		return ownerReadUnspecified
	}
	return e.check
}
func (e *OwnerIdentityReadFailure) Detail() OwnerIdentityReadCheck {
	if e == nil {
		return ownerReadUnspecified
	}
	var inner *OwnerIdentityReadFailure
	if errors.As(e.cause, &inner) {
		return inner.Check()
	}
	return ownerReadUnspecified
}
func (e *OwnerIdentityReadFailure) Error() string {
	return "owner identity unavailable: check=" + e.Check().String() + " detail=" + e.Detail().String()
}
func (e *OwnerIdentityReadFailure) Unwrap() error { return e.cause }

// FixedStep names the failed check and any nested closed step, e.g.
// initial-guard or projections/credentials-content.
func (e *OwnerIdentityReadFailure) FixedStep() string {
	var nested interface{ FixedStep() string }
	if errors.As(e.cause, &nested) {
		return e.Check().String() + "/" + nested.FixedStep()
	}
	if errors.Is(e.cause, context.DeadlineExceeded) {
		return e.Check().String() + "/deadline"
	}
	if errors.Is(e.cause, context.Canceled) {
		return e.Check().String() + "/cancelled"
	}
	return e.Check().String()
}
func ownerReadAnnotate(check *OwnerIdentityReadCheck, result *error) {
	if *result != nil {
		*result = &OwnerIdentityReadFailure{check: *check, cause: *result}
	}
}
