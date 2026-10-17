package contracts

// HubWorkerClusterObservationTokenFile is a native projected token for the local HWORK
// observation request only. It is not a Kubernetes API or effect credential.
// The audience is fleet.ClusterObservationAudience(installationID); the Pod UID
// hint uses OwnerPodUIDEnvironment, populated from metadata.uid.
const HubWorkerClusterObservationTokenFile = "cluster-observation.token"
