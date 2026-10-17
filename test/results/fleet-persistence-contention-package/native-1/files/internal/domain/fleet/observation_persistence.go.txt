package fleet

// ErrObservationPersistenceContended is a failed unchanged-source persistence
// attempt, not an accepted observation, authority, or retry hint. Consumers keep
// the prior original expiry. It remains unavailable to ordinary callers.
var ErrObservationPersistenceContended error = observationPersistenceContended{}

type observationPersistenceContended struct{}

func (observationPersistenceContended) Error() string {
	return "unchanged fleet observation persistence contended"
}
func (observationPersistenceContended) Unwrap() error { return ErrUnavailable }
