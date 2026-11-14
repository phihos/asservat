package postgres

// ProvisionStop names the fixed provisioning step and purpose that stopped,
// for an operator diagnostic that carries no SQL or Kubernetes text.
type ProvisionStop struct {
	Step string
	Err  error
}

func (e *ProvisionStop) Error() string     { return "provisioning stopped at " + e.Step }
func (e *ProvisionStop) Unwrap() error     { return e.Err }
func (e *ProvisionStop) FixedStep() string { return e.Step }
func provisionStop(step string, err error) error {
	return &ProvisionStop{Step: step, Err: err}
}
