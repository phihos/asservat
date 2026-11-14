package kubernetes

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// InitialPreparer is an installation-only producer. A root receipt is public
// provenance, never a witness, cleanliness assertion, or recovery authority.
// The continuity bootstrap and its independent probe are operator-owned inputs.
type InitialPreparer struct {
	handoverConflicts map[string]initialHandoverConflict
	secretCompletions map[string]contracts.WorkerObjectReference
	providers         *contracts.InitialProviderProfile
	providerResponses map[string]contracts.InitialProviderResponse
	services          *contracts.InitialPreparationServices
	plan              contracts.InitialPreparationPlan
	rootUID           string
	creator           *InitialNamespaceCreator
	protection        *configMapProtection
	staging           GuardPin
	objects           []initialPreparationResource
	requestMu         sync.Mutex
	requestOwner      string
	requestClosed     bool
	requestJoin       sync.WaitGroup
	requestCancel     context.CancelFunc
	requestContext    context.Context
	requestProofs     map[string]contracts.InitialPreparationPodRequestCompletion
	probeResponses    map[string]contracts.InitialPreparationProbeResponse
}

func prepUUID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", cfg.ErrUnavailable
	}
	b[6], b[8] = b[6]&15|64, b[8]&63|128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
