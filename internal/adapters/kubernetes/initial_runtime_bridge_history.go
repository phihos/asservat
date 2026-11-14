package kubernetes

// InitialRuntimeBridgeHistory recognizes only the positively acknowledged final
// bridge. Its constructor holds no SQL administrator/effect facet. It permits
// the existing SELECT-only initial history reader to remain diagnostic during
// later recovery/suspension; it cannot complete a pending bridge or revive any
// installation credential. The original no-bridge history path is unchanged.
type InitialRuntimeBridgeHistory struct{ bridge *InitialRuntimeBridge }
