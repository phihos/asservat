package analysis

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// get_http_headers (REQ-NET-004, ADR-282 slice 4) pages the approved records
// of one stored `http-response-headers/v1` projection. These are pure values:
// structural validity is neither read authority nor verification of the
// stored document, which the regional reader rechecks before any record.
const (
	HTTPHeaderPageRecords   = 100
	HTTPHeaderMaxRecords    = 32_760 // the projector's record cap within 16 MiB
	HTTPHeaderMaxFields     = 32
	HTTPHeaderMaxGaps       = 32
	HTTPHeaderMaxCount      = 1_000_000_000_000
	httpHeaderBindingDigits = 32
)

// ErrInvalidCursor is a cursor that is malformed, beyond the projection or
// issued for a different projection. It discloses nothing about the artifact.
var ErrInvalidCursor = errors.New("invalid http header cursor")

// HTTPHeaderSelection is the normalized public input. Start is the index of
// the first record; Binding is the projection-digest prefix a cursor carries
// (empty on the first page). It names no source, worker, key or deadline.
type HTTPHeaderSelection struct {
	CaseID, ArtifactID string
	Start, Limit       int
	Binding            string
}

func (s HTTPHeaderSelection) Valid() bool {
	if !authorization.UUID(s.CaseID) || !authorization.UUID(s.ArtifactID) || s.Limit < 1 || s.Limit > HTTPHeaderPageRecords ||
		s.Start < 0 || s.Start >= HTTPHeaderMaxRecords {
		return false
	}
	if s.Start == 0 {
		return s.Binding == ""
	}
	return lowerHex(s.Binding, httpHeaderBindingDigits)
}

// NormalizeHTTPHeaderSelection applies the canonical defaults: no cursor
// starts at the first record, an omitted (zero) limit is the 100-record page.
func NormalizeHTTPHeaderSelection(caseID, artifactID, cursor string, limit int) (HTTPHeaderSelection, error) {
	if limit == 0 {
		limit = HTTPHeaderPageRecords
	}
	s := HTTPHeaderSelection{CaseID: caseID, ArtifactID: artifactID, Limit: limit}
	if cursor != "" {
		index, binding, ok := strings.Cut(cursor, ":")
		n, err := strconv.Atoi(index)
		if !ok || err != nil || len(index) > 7 || index != strconv.Itoa(n) || n < 1 {
			return HTTPHeaderSelection{}, ErrInvalidCursor
		}
		s.Start, s.Binding = n, binding
	}
	if !s.Valid() {
		if cursor != "" && authorization.UUID(caseID) && authorization.UUID(artifactID) && limit >= 1 && limit <= HTTPHeaderPageRecords {
			return HTTPHeaderSelection{}, ErrInvalidCursor
		}
		return HTTPHeaderSelection{}, ErrInvalid
	}
	return s, nil
}

// Matches reports whether a cursor was issued for this projection digest.
func (s HTTPHeaderSelection) Matches(d artifact.Digest) bool {
	return s.Start == 0 && s.Binding == "" || s.Start > 0 && s.Binding == httpHeaderBinding(d)
}

// HTTPHeaderCursor is the opaque continuation: the next record index bound
// to the projection digest. It is not a permit; every call reauthorizes.
func HTTPHeaderCursor(next int, d artifact.Digest) string {
	return strconv.Itoa(next) + ":" + httpHeaderBinding(d)
}

func httpHeaderBinding(d artifact.Digest) string {
	return fmt.Sprintf("%x", d[:httpHeaderBindingDigits/2])
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type HTTPHeaderField struct {
	Name, Value string
}

// HTTPHeaderRecord is one approved request/response pair. Status zero is a
// partial record without a final response.
type HTTPHeaderRecord struct {
	Timestamp time.Time
	Method    string
	Status    int
	Headers   []HTTPHeaderField
	Partial   bool
}

var httpHeaderMethods = map[string]bool{"": true, "GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true, "CONNECT": true, "OPTIONS": true, "TRACE": true, "PATCH": true, "OTHER": true}

var httpCredentialHeaders = map[string]bool{"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true}

func (r HTTPHeaderRecord) Valid() bool {
	if r.Timestamp.IsZero() || r.Timestamp.Year() < 1970 || r.Timestamp.Year() > 9999 || !httpHeaderMethods[r.Method] ||
		r.Status == 0 && !r.Partial || r.Status != 0 && (r.Status < 100 || r.Status > 599) || len(r.Headers) > HTTPHeaderMaxFields {
		return false
	}
	for _, h := range r.Headers {
		if len(h.Name) < 1 || len(h.Name) > 128 || httpCredentialHeaders[h.Name] || len(h.Value) < 1 || len(h.Value) > 1024 || !utf8.ValidString(h.Value) {
			return false
		}
		for _, c := range h.Name {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// HTTPHeaderPage is the exact requested slice of a rechecked projection with
// its whole-document gap report. Total is the projection's record count.
type HTTPHeaderPage struct {
	ProjectionDigest              artifact.Digest
	Start, Total                  int
	Records                       []HTTPHeaderRecord
	DroppedFlows, IncompleteFlows uint64
	CoverageGaps                  []string
}

// Valid requires exactly the selected records (never silently fewer), in
// time order, and a bounded gap report.
func (p HTTPHeaderPage) Valid(s HTTPHeaderSelection) bool {
	if !s.Valid() || p.ProjectionDigest == (artifact.Digest{}) || !s.Matches(p.ProjectionDigest) || p.Start != s.Start ||
		p.Total < 0 || p.Total > HTTPHeaderMaxRecords || p.Start > p.Total || s.Start > 0 && s.Start >= p.Total ||
		len(p.Records) != min(s.Limit, p.Total-p.Start) || p.DroppedFlows > HTTPHeaderMaxCount || p.IncompleteFlows > HTTPHeaderMaxCount ||
		len(p.CoverageGaps) > HTTPHeaderMaxGaps {
		return false
	}
	for i, r := range p.Records {
		if !r.Valid() || i > 0 && r.Timestamp.Before(p.Records[i-1].Timestamp) {
			return false
		}
	}
	for _, g := range p.CoverageGaps {
		if len(g) < 1 || len(g) > 128 || !utf8.ValidString(g) {
			return false
		}
	}
	return true
}

// Next is the continuation after the first n delivered records, or "" when
// they reach the end of the projection.
func (p HTTPHeaderPage) Next(n int) string {
	if n < 1 || n > len(p.Records) || p.Start+n >= p.Total {
		return ""
	}
	return HTTPHeaderCursor(p.Start+n, p.ProjectionDigest)
}

// HTTPHeaderReadAuthority is C-03's current ordinary read decision for one
// published httpHeaders extract: ReadApproved under evidence:read, the
// original audience and every retained policy origin. Version is the
// verified ciphertext-copy version reported as provenance. It is an internal
// decision with its original interval, not a stored or renewable permit.
type HTTPHeaderReadAuthority struct {
	CaseID, ArtifactID, CaptureID string
	NativeType, Format, DataClass string
	Version                       artifact.Digest
	Principal                     identity.Principal
	AccessUntil                   time.Time
	ObservedAt, ValidUntil        time.Time
}

func (a HTTPHeaderReadAuthority) Valid(now time.Time) bool {
	return authorization.UUID(a.CaseID) && authorization.UUID(a.ArtifactID) && authorization.UUID(a.CaptureID) &&
		a.NativeType == artifact.HTTPHeadersArtifact && a.Format == artifact.HTTPHeadersFormat && a.DataClass == "extract" &&
		a.Version != (artifact.Digest{}) && a.Principal.Valid() && !now.Before(a.ObservedAt) && now.Before(a.ValidUntil) &&
		now.Before(a.AccessUntil)
}

// SameSource reports whether a later decision covers the same published
// source and caller; its own interval may differ.
func (a HTTPHeaderReadAuthority) SameSource(b HTTPHeaderReadAuthority) bool {
	return a.CaseID == b.CaseID && a.ArtifactID == b.ArtifactID && a.CaptureID == b.CaptureID && a.NativeType == b.NativeType &&
		a.Format == b.Format && a.DataClass == b.DataClass && a.Version == b.Version && a.Principal == b.Principal
}
