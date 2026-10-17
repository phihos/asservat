package audit

// These private privacy decisions never enter public tool discovery.
func (r OperationIntent) processingOperation() bool {
	return r.Name == "initialize_processing" || r.Name == "restrict_processing" || r.Name == "release_processing"
}
