package fleet

import "time"

// Actual role resolution and grants are separately supplied by protected SQL
// installation. These bounded names never become ambient or caller-selected
// credentials. A name/OID/incarnation mismatch must deny after restoration.
type ConnectorIdentityRoles struct{ Source, Journal, Acknowledgement, Cleanup, Verifier, Finalizer string }

func (r ConnectorIdentityRoles) Valid() bool {
	seen := map[string]bool{}
	for _, name := range []string{r.Source, r.Journal, r.Acknowledgement, r.Cleanup, r.Verifier, r.Finalizer} {
		if len(name) < 1 || len(name) > 63 || seen[name] {
			return false
		}
		seen[name] = true
		for i, c := range name {
			if !(c >= 'a' && c <= 'z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
				return false
			}
		}
	}
	return true
}

type ConnectorIdentitySource struct {
	Observation ConnectorCredentialObservation
	Roles       ConnectorIdentityRoles
}

func (s ConnectorIdentitySource) Valid(now time.Time) bool {
	return s.Observation.Backing.Valid() && s.Roles.Valid() && s.Observation.Profile.Valid() && s.Observation.ObservedAt.Before(s.Observation.FreshUntil) && !now.Before(s.Observation.ObservedAt) && now.Before(s.Observation.FreshUntil) && !s.Observation.FreshUntil.After(s.Observation.ObservedAt.Add(5*time.Second))
}
