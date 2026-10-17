package identity

import "time"

// BrowserBinding pins the private runtime composition to the same authority
// and origin as the independently observed administrator configuration.
type BrowserBinding struct {
	RootID, Epoch, Issuer, ClientID, Origin string
}

func (b BrowserBinding) Valid() bool {
	return browserUUID(b.RootID) && browserUUID(b.Epoch) && Text(b.Issuer, 2048) && Text(b.ClientID, 256) && Text(b.Origin, 2048)
}

// BrowserSettings is a current protected installation projection. Its epoch is
// operational session identity, not a tenant or a policy execution identity.
// Provider endpoints/keys remain separately qualified bootstrap dependencies.
type BrowserSettings struct {
	RootID, Epoch, Issuer, ClientID, Origin                     string
	Revision                                                    Revision
	Suspended                                                   bool
	MaxLifetimeSeconds, MaxLogins, MaxSessions, MaxLogoutEvents int
	ObservedAt, FreshUntil                                      time.Time
}

func browserUUID(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (s BrowserSettings) Valid(now time.Time) bool {
	return s.Binding().Valid() && s.Revision.Valid() && s.MaxLifetimeSeconds >= 60 && s.MaxLifetimeSeconds <= 86400 && s.MaxLogins >= 1 && s.MaxLogins <= 10000 && s.MaxSessions >= 1 && s.MaxSessions <= 100000 && s.MaxLogoutEvents >= 1 && s.MaxLogoutEvents <= 100000 && Fresh(s.ObservedAt, s.FreshUntil, now, 5*time.Second)
}

func (s BrowserSettings) Binding() BrowserBinding {
	return BrowserBinding{s.RootID, s.Epoch, s.Issuer, s.ClientID, s.Origin}
}
