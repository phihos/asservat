package contracts

// specs/persistence.md: at most 32 pooled connections per hub replica, with an
// installation-wide allocation that leaves maintenance headroom.
const SQLConnectionsPerHubReplica = 32
