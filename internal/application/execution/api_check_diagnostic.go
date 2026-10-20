package execution

// apiCheckStep distinguishes the fixed current-check boundary without reading
// provider text or trusting a dependency's diagnostic labels. Its original
// error remains available through errors.Is/As; no authority result changes.
type apiCheckStep struct {
	step string
	err  error
}

func (e apiCheckStep) Error() string     { return "api context check " + e.step }
func (e apiCheckStep) Unwrap() error     { return e.err }
func (e apiCheckStep) FixedStep() string { return e.step }
