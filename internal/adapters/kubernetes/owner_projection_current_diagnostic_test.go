package kubernetes

type fixedSQLStep struct{ error }

func (fixedSQLStep) FixedStep() string { return "owner projection SQL: finalize-final-read" }
