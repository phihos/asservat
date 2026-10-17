package contracts

// Explicit installer-selected capability. Omission retains the original opaque
// provider projection and Pod bytes. Credential content remains private.
const InitialRegistryAuthentication = "dockerconfigjson/v1"
const InitialRegistryMaxBytes = 4 << 10
const InitialProviderMaterialMaxBytes = 8 << 10
