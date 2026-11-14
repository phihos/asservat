package identity

import "time"

// BrowserSettings is browser.json of the Helm-rendered settings ConfigMap.
// A session ends at creation plus MaxLifetime or InactivityTimeout after its
// last authenticated request, whichever comes first.
type BrowserSettings struct {
	Issuer, ClientID, Origin       string
	MaxLifetime, InactivityTimeout time.Duration
}

func (s BrowserSettings) Valid() bool {
	return Text(s.Issuer, 2048) && Text(s.ClientID, 256) && Text(s.Origin, 2048) && s.MaxLifetime >= time.Second && s.InactivityTimeout >= time.Second
}
