package identity

import "time"

// PolicyGrantApproval is protected installation configuration, independent
// of a person's token/session lifetime. Grant issuance/clamping belongs to C-03.
type PolicyGrantApproval struct{ DefaultAge, MaxAge, RenewalNotice time.Duration }

func (p PolicyGrantApproval) Valid() bool {
	return p.DefaultAge >= time.Second && p.MaxAge >= p.DefaultAge && p.MaxAge <= 365*24*time.Hour && p.RenewalNotice >= time.Second && p.RenewalNotice <= p.MaxAge && p.DefaultAge%time.Second == 0 && p.MaxAge%time.Second == 0 && p.RenewalNotice%time.Second == 0
}

func DefaultPolicyGrantApproval() PolicyGrantApproval {
	return PolicyGrantApproval{DefaultAge: 7 * 24 * time.Hour, MaxAge: 30 * 24 * time.Hour, RenewalNotice: 24 * time.Hour}
}

// PolicyGrantSettingsObservation is one protected accepted-settings candidate.
// Its original source times survive cache reuse; it is not raw revision history.
type PolicyGrantSettingsObservation struct {
	Issuer                 string
	Revision               Revision
	Values                 PolicyGrantApproval
	ObservedAt, FreshUntil time.Time
}

func (p PolicyGrantSettingsObservation) Valid(now time.Time) bool {
	return Text(p.Issuer, 2048) && p.Revision.Valid() && p.Values.Valid() && Fresh(p.ObservedAt, p.FreshUntil, now, 30*time.Second)
}
