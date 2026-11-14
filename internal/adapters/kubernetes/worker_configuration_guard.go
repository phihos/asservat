package kubernetes

// WorkerConfigurationProtection names the worker profile ConfigMap and
// carries its deterministic source digest (NewPlainWorkerConfigurationProtection).
type WorkerConfigurationProtection struct{ *configMapProtection }
