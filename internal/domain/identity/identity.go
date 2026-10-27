// Package identity contains verified identity values and pure admission rules.
// Values are not credentials: only checked ingress and current policy supply them.
package identity

import (
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalid     = errors.New("invalid identity input")
	ErrDenied      = errors.New("identity not eligible")
	ErrUnavailable = errors.New("identity authority unavailable")
)

// EvidenceReadRequestWindow bounds one public evidence-read request
// (get_file_excerpt, get_query_result, prepare_artifact_download,
// get_artifact_download); other public requests keep five seconds. Installed
// native78-80 showed the approved read's audit, authorization, SQL fences,
// worker wake-up, three key unwraps and the object read cannot complete within
// five seconds. It bounds only the request itself: every identity, authority,
// observation and lease inside it keeps its own shorter ValidUntil.
const EvidenceReadRequestWindow = 20 * time.Second

type Kind string

const (
	Human    Kind = "human"
	Workload Kind = "workload"
)

type Principal struct {
	Issuer, Subject, ClientID string
	Kind                      Kind
}
type Revision struct {
	UID        string
	Generation int64
	Digest     [32]byte
}

// Claims is the output of a token verifier, never decoded client JSON.
// KeyUntil bounds the key snapshot used to verify the signature.
type Claims struct {
	Issuer, Subject, ClientID     string
	Scopes, Groups                []string
	IssuedAt, ExpiresAt, KeyUntil time.Time
	// ACR and AuthTime are the optional signed acr/auth_time claims (ADR-249).
	// They are IdP assurance facts, never a client checkbox or a cookie.
	ACR      string
	AuthTime time.Time
}

// StepUpPolicy names the protected installation's accepted step-up assurance
// (ADR-249, REQ-AUT-003): a signed acr value among ACRValues whose auth_time
// is at most MaxAge old. The zero value configures no step-up, so no approval
// can be decided.
type StepUpPolicy struct {
	ACRValues []string
	MaxAge    time.Duration
}

// Configured reports whether an approval step-up is configured at all.
func (s StepUpPolicy) Configured() bool { return len(s.ACRValues) > 0 }

func (s StepUpPolicy) valid() bool {
	if !s.Configured() {
		return s.MaxAge == 0
	}
	return len(s.ACRValues) <= 8 && Strings(s.ACRValues, 8, 128) && s.MaxAge >= 30*time.Second && s.MaxAge <= time.Hour
}

// Assurance is the verified authentication context of one identity
// observation. StepUpUntil is zero unless the signed acr matched the accepted
// step-up policy; it never outlives the observation.
type Assurance struct {
	ACR                          string
	AuthenticatedAt, StepUpUntil time.Time
}

// Client pins identity class only for a qualified issuer/client configuration
// which cannot issue another class under the same client. Mixed clients require
// a future qualified mapping, not a human-by-default fallback.
type Client struct {
	ID             string
	Kind           Kind
	ClassQualified bool
}
type Subject struct {
	ID   string
	Kind Kind
}

// Policy is an accepted protected installation projection, not a public API.
// GroupsAtIssueQualified attests complete stable group IDs refreshed at iat,
// including refresh-token issuance. Group display names are not acceptable IDs.
type Policy struct {
	Revision               Revision
	Issuer                 string
	ObservedAt, FreshUntil time.Time
	Clients                []Client
	EligibleSubjects       []Subject
	EligibleGroups         []string
	GroupsAtIssueQualified bool
	GroupMaxAge            time.Duration
	// StepUp and RequireRecordingApproval are the protected installation
	// approval settings (ADR-249). RequireRecordingApproval is the REQ-SYS-002
	// "unless an administrator requires more" switch: metadata packet/syscall
	// recordings then need the same individual approval as sensitive ones.
	StepUp                   StepUpPolicy
	RequireRecordingApproval bool
}

type Identity struct {
	Principal              Principal
	Scopes, Groups         []string
	Policy                 Revision
	VerifiedAt, ValidUntil time.Time
	Assurance              Assurance
}

// SteppedUp reports a current IdP step-up of a human identity (ADR-249).
func (i Identity) SteppedUp(now time.Time) bool {
	return i.Principal.Kind == Human && !i.Assurance.StepUpUntil.IsZero() && now.Before(i.Assurance.StepUpUntil) && !i.Assurance.AuthenticatedAt.After(now)
}

func Text(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}
func ValidKind(k Kind) bool { return k == Human || k == Workload }
func (r Revision) Valid() bool {
	return Text(r.UID, 64) && r.Generation > 0 && r.Generation <= 2147483647 && r.Digest != ([32]byte{})
}
func (p Principal) Valid() bool {
	return Text(p.Issuer, 2048) && Text(p.Subject, 256) && Text(p.ClientID, 256) && ValidKind(p.Kind)
}
func Strings(v []string, maxCount, maxLength int) bool {
	if len(v) > maxCount {
		return false
	}
	seen := make(map[string]bool, len(v))
	for _, s := range v {
		if !Text(s, maxLength) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func Fresh(observed, until, now time.Time, maximum time.Duration) bool {
	return !observed.IsZero() && !observed.After(now) && until.After(observed) && !until.After(observed.Add(maximum)) && now.Before(until)
}
func Earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (p Policy) Validate(now time.Time) error {
	if !p.Revision.Valid() || !Text(p.Issuer, 2048) || !Fresh(p.ObservedAt, p.FreshUntil, now, 60*time.Second) || len(p.Clients) < 1 || len(p.Clients) > 64 || len(p.EligibleSubjects) > 256 || len(p.EligibleGroups) > 256 || len(p.EligibleSubjects)+len(p.EligibleGroups) == 0 || !p.GroupsAtIssueQualified || p.GroupMaxAge <= 0 || p.GroupMaxAge > 5*time.Minute || !Strings(p.EligibleGroups, 256, 256) || !p.StepUp.valid() {
		return ErrUnavailable
	}
	clients := map[string]bool{}
	for _, c := range p.Clients {
		if !Text(c.ID, 256) || !ValidKind(c.Kind) || !c.ClassQualified || clients[c.ID] {
			return ErrUnavailable
		}
		clients[c.ID] = true
	}
	seen := map[Subject]bool{}
	for _, s := range p.EligibleSubjects {
		if !Text(s.ID, 256) || !ValidKind(s.Kind) || seen[s] {
			return ErrUnavailable
		}
		seen[s] = true
	}
	return nil
}

// Admit cannot turn a valid issuer token into membership without the explicit
// organization policy. Freshness is intersected, never renewed at verification.
func Admit(c Claims, p Policy, now time.Time) (Identity, error) {
	var out Identity
	if p.Validate(now) != nil {
		return out, ErrUnavailable
	}
	if c.Issuer != p.Issuer || !Text(c.Subject, 256) || !Text(c.ClientID, 256) || !Strings(c.Scopes, 64, 128) || !Strings(c.Groups, 256, 256) || c.IssuedAt.IsZero() || c.IssuedAt.After(now) || !c.ExpiresAt.After(c.IssuedAt) || !now.Before(c.ExpiresAt) || !now.Before(c.KeyUntil) {
		return out, ErrDenied
	}
	var kind Kind
	for _, client := range p.Clients {
		if client.ID == c.ClientID {
			kind = client.Kind
		}
	}
	if !ValidKind(kind) {
		return out, ErrDenied
	}
	eligible := slices.Contains(p.EligibleSubjects, Subject{c.Subject, kind})
	for _, g := range c.Groups {
		eligible = eligible || slices.Contains(p.EligibleGroups, g)
	}
	until := Earlier(Earlier(c.ExpiresAt, c.KeyUntil), Earlier(p.FreshUntil, c.IssuedAt.Add(p.GroupMaxAge)))
	if !eligible || !now.Before(until) {
		return out, ErrDenied
	}
	return Identity{Principal{c.Issuer, c.Subject, c.ClientID, kind}, slices.Clone(c.Scopes), slices.Clone(c.Groups), p.Revision, now, until, assurance(c, p, kind, now, until)}, nil
}

// assurance derives step-up only from the signed acr/auth_time of a human
// token and the protected policy; it ends at the earlier of auth_time+MaxAge
// and the identity's own validity.
func assurance(c Claims, p Policy, kind Kind, now, until time.Time) Assurance {
	if c.ACR == "" || !Text(c.ACR, 128) {
		return Assurance{}
	}
	a := Assurance{ACR: c.ACR}
	if c.AuthTime.IsZero() || c.AuthTime.After(now) {
		return a
	}
	a.AuthenticatedAt = c.AuthTime
	if kind == Human && p.StepUp.Configured() && slices.Contains(p.StepUp.ACRValues, c.ACR) {
		if end := Earlier(c.AuthTime.Add(p.StepUp.MaxAge), until); now.Before(end) {
			a.StepUpUntil = end
		}
	}
	return a
}

func (i Identity) Valid(now time.Time) bool {
	return i.Principal.Valid() && i.Policy.Valid() && Strings(i.Scopes, 64, 128) && Strings(i.Groups, 256, 256) && Fresh(i.VerifiedAt, i.ValidUntil, now, 60*time.Second)
}
