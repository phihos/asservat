// Package identity contains verified identity values and pure admission rules.
// Values are not credentials: only checked ingress and current policy supply them.
package identity

import (
	"errors"
	"math"
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
// (get_file_excerpt, get_http_headers, get_query_result, prepare_artifact_download,
// get_artifact_download); ordinary public requests keep five seconds except
// RecordingSaveRequestWindow or CapturePreviewRequestWindow composition. Installed
// native78-80 showed the approved read's audit, authorization, SQL fences,
// worker wake-up, three key unwraps and the object read cannot complete within
// five seconds. It bounds only the request itself: every identity, authority,
// observation and lease inside it keeps its own shorter ValidUntil.
const EvidenceReadRequestWindow = 20 * time.Second

// AuthorityRecheckInterval bounds how long one operation's authority snapshot
// (identity, eligibility, recovery) may be used before it is checked again
// (ADR-311). It never extends an original session, grant, retention or source
// deadline. Downloads already used this interval (ADR-220/258).
const AuthorityRecheckInterval = 30 * time.Second

// RecordingSaveRequestWindow bounds the composed admission/start/history request.
// Each accepted snapshot retains its original T0+5s StartBy.
const RecordingSaveRequestWindow = 15 * time.Second

// CapturePreviewRequestWindow bounds history lookup plus fresh preview creation.
// Settings reads keep five seconds; history-backed Go profile preview
// composition selects eight seconds up front. Independent observations retain
// their own original five-second bounds.
const CapturePreviewRequestWindow = 15 * time.Second

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

// StepUpPolicy is the optional approval step-up (ADR-249, ADR-335 D5): a
// signed acr value among ACRValues whose auth_time is at most MaxAge old. The
// zero value configures none; approvals then need no step-up.
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
	return Distinct(s.ACRValues) && s.MaxAge > 0
}

// Assurance is the verified authentication context of one identity
// observation. StepUpUntil is zero unless the signed acr matched the accepted
// step-up policy; it never outlives the observation.
type Assurance struct {
	ACR                          string
	AuthenticatedAt, StepUpUntil time.Time
}

// Client pins identity class for a registered client.
type Client struct {
	ID             string
	Kind           Kind
	ClassQualified bool
}

// Subject is a principal ID with its identity class.
type Subject struct {
	ID   string
	Kind Kind
}

// Policy is the protected installation identity settings (identity.json).
// Groups are read by name from GroupsClaim and valid until the token expires.
// Empty RequiredGroups admits every authenticated user of a registered client.
type Policy struct {
	Revision                   Revision
	Issuer                     string
	ObservedAt, FreshUntil     time.Time
	Clients                    []Client
	GroupsClaim, UsernameClaim string
	RequiredGroups             []string
	StepUp                     StepUpPolicy
	PolicyGrants               *PolicyGrantApproval
	// AdministratorGroups and AdministratorSubjects are identity.administrators
	// (ADR-335 D14): the installation administrators.
	AdministratorGroups, AdministratorSubjects []string
}

// Administrator reports whether i is an installation administrator: a
// listed subject or a member of a listed group of the policy's issuer.
func (p Policy) Administrator(i Identity) bool {
	if i.Principal.Kind != Human || i.Principal.Issuer != p.Issuer {
		return false
	}
	return slices.Contains(p.AdministratorSubjects, i.Principal.Subject) || slices.ContainsFunc(i.Groups, func(g string) bool { return slices.Contains(p.AdministratorGroups, g) })
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

// Distinct reports distinct, non-empty, control-free strings. The 1 MiB
// ConfigMap that carries them bounds their length.
func Distinct(v []string) bool { return Strings(v, len(v), math.MaxInt) }

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
	if !p.Revision.Valid() || !Text(p.Issuer, 2048) || !Fresh(p.ObservedAt, p.FreshUntil, now, 60*time.Second) || len(p.Clients) < 1 || !Distinct(p.RequiredGroups) || !p.StepUp.valid() || p.PolicyGrants != nil && !p.PolicyGrants.Valid() {
		return ErrUnavailable
	}
	clients := map[string]bool{}
	for _, c := range p.Clients {
		if !Text(c.ID, 256) || !ValidKind(c.Kind) || !c.ClassQualified || clients[c.ID] {
			return ErrUnavailable
		}
		clients[c.ID] = true
	}
	return nil
}

// Admit admits a verified token of a registered client. Freshness is
// intersected, never renewed at verification.
func Admit(c Claims, p Policy, now time.Time) (Identity, error) {
	var out Identity
	if p.Validate(now) != nil {
		return out, ErrUnavailable
	}
	if c.Issuer != p.Issuer || !Text(c.Subject, 256) || !Text(c.ClientID, 256) || !Distinct(c.Scopes) || !Distinct(c.Groups) || c.IssuedAt.IsZero() || c.IssuedAt.After(now) || !c.ExpiresAt.After(c.IssuedAt) || !now.Before(c.ExpiresAt) || !now.Before(c.KeyUntil) {
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
	if len(p.RequiredGroups) > 0 && !slices.ContainsFunc(c.Groups, func(g string) bool { return slices.Contains(p.RequiredGroups, g) }) {
		return out, ErrDenied
	}
	until := Earlier(Earlier(c.ExpiresAt, c.KeyUntil), p.FreshUntil)
	if !now.Before(until) {
		return out, ErrDenied
	}
	return Identity{Principal{c.Issuer, c.Subject, c.ClientID, kind}, slices.Clone(c.Scopes), slices.Clone(c.Groups), p.Revision, now, until, assurance(c, p, kind, now, until)}, nil
}

// assurance derives step-up from the signed acr/auth_time of a human token
// and the protected policy; it ends at the earlier of auth_time+MaxAge and the
// identity's own validity. Without a configured step-up every human identity
// satisfies it for its own validity (ADR-335 D5).
func assurance(c Claims, p Policy, kind Kind, now, until time.Time) Assurance {
	var a Assurance
	if kind == Human && !p.StepUp.Configured() {
		a.StepUpUntil = until
	}
	if c.ACR == "" || !Text(c.ACR, 128) {
		return a
	}
	a.ACR = c.ACR
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
	return i.Principal.Valid() && i.Policy.Valid() && Distinct(i.Scopes) && Distinct(i.Groups) && Fresh(i.VerifiedAt, i.ValidUntil, now, 60*time.Second)
}
