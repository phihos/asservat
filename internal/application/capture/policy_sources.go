package capture

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// PolicySourceCheck is private same-operation producer input. No HTTP, MCP or
// authored policy can supply these current observations or choose source credit.
// SourceID/Fence are fixed once for uncertain insertion/replay. Positive credit
// is conservative spend; zero renewal retains the original cumulative allowance.
type PolicySourceCheck struct {
	Policy                                                          value.RestartPolicy
	Authority                                                       authorization.AcceptedPolicyAuthority
	Target                                                          targets.PodResolution
	Node                                                            targets.PacketSourceObservation
	Recovery                                                        artifact.RecoveryProof
	Retention                                                       privacy.Resolution
	Settings                                                        identity.Policy
	SourceID, Fence                                                 string
	BytesPerSecond, InitialCredit, ExpectedCredit, AdditionalCredit int64
	SourceSlots                                                     int64
	Initial                                                         bool
	ObservedAt, ValidUntil                                          time.Time
}

// PolicySourceAdmission is an original committed source grant. Node lowering
// limits describe current administration, not a second acquisition permit.
type PolicySourceAdmission struct {
	Permit    collector.SourcePermit
	Resources collector.SourceResources
	First     bool
}

type PolicySourceState struct {
	Binding                              collector.SourceBinding
	ClusterID, NamespaceUID, WorkloadUID string
	StartedAt, HardUntil, StartBy        time.Time
	InitialLeafUntil                     time.Time
	InitialCredit                        int64
	Credit, BytesPerSecond               int64
	EndedAt                              time.Time
}

type PolicySourceLedger interface {
	AdmitSource(context.Context, PolicySourceCheck) (PolicySourceAdmission, error)
	ListSources(context.Context, string) ([]PolicySourceState, error)
	EndSource(context.Context, string) error
	SweepSources(context.Context) ([]PolicySourceState, error)
}

// PolicySourceDispatcher authenticates a purpose-separated source message to
// the original region/node process. Enqueue or ACK is not fresh authority.
type PolicySourceDispatcher interface {
	DispatchSource(context.Context, targets.PodResolution, targets.PacketSourceObservation, collector.PacketSource) error
	StopSource(context.Context, string, collector.SourceBinding) error
}
