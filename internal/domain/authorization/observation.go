package authorization

// ObservationLimits bounds input entering a sensitive parser/predicate, not
// retained output. Event limits are retained in reviewed scope for future
// syscall arguments; absence never authorizes argument-mode acquisition.
type ObservationLimits struct {
	MaxSessionSeconds, MaxObservedBytes, MaxBytesPerSecond, MaxConcurrentSessions int64
	MaxObservedEvents                                                             int64 `json:",omitempty"`
}

func (o ObservationLimits) Valid() bool {
	return o.MaxSessionSeconds >= 1 && o.MaxSessionSeconds <= 3600 && o.MaxObservedBytes >= 1 && o.MaxObservedBytes <= 1<<40 && o.MaxBytesPerSecond >= 1 && o.MaxBytesPerSecond <= 1<<30 && o.MaxConcurrentSessions >= 1 && o.MaxConcurrentSessions <= 1000 && o.MaxObservedEvents >= 0 && o.MaxObservedEvents <= 1_000_000_000
}

// Within permits a reviewed grant to narrow the resolved policy/recipe bounds.
// An omitted event ceiling cannot authorize future argument-mode event reads.
func (o ObservationLimits) Within(ceiling ObservationLimits) bool {
	return o.Valid() && ceiling.Valid() && o.MaxSessionSeconds <= ceiling.MaxSessionSeconds && o.MaxObservedBytes <= ceiling.MaxObservedBytes && o.MaxBytesPerSecond <= ceiling.MaxBytesPerSecond && o.MaxConcurrentSessions <= ceiling.MaxConcurrentSessions && o.MaxObservedEvents <= ceiling.MaxObservedEvents
}
