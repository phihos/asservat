package fleet

// ConnectorRetirementProof identifies the actual live actor for one protected
// retirement audit. It is not process enrollment, credential, serving, or backing
// promotion authority. Ordinary proof validation rejects this suspended source.
// Retirement must be acknowledged before workload teardown; later historical
// cleanup uses its immutable accepted result, not a fabricated live actor.
type ConnectorRetirementProof ConnectorProcessProof
