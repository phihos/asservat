package presentation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/httpheaders"
	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

const (
	headerCase     = "00000000-0000-4000-8000-000000000070"
	headerArtifact = "00000000-0000-4000-8000-000000000071"
	headerCapture  = "00000000-0000-4000-8000-000000000072"
	headerRequest  = "00000000-0000-4000-8000-000000000073"
)

var headerPrincipal = identity.Principal{Issuer: "https://id.example.invalid", Subject: "dev", ClientID: "mcp", Kind: identity.Human}

// headerFixture composes the real C-18 service with a synthetic C-03
// decision and a C-14 reader that rechecks a stored synthetic projection
// through httpheaders.ReadPage, as the regional reader must.
type headerFixture struct {
	now        time.Time
	scopes     []string
	native     []byte
	authority  value.HTTPHeaderReadAuthority
	authErr    error
	revokeRead bool
	authCalls  int
}

func (f *headerFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	return identity.Identity{Principal: headerPrincipal, Scopes: f.scopes, Groups: []string{"team-a"}, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: f.now, ValidUntil: f.now.Add(30 * time.Second)}, nil
}

func (f *headerFixture) CurrentHTTPHeaderRead(_ context.Context, _ identities.CurrentIdentity, caseID, artifactID string) (value.HTTPHeaderReadAuthority, error) {
	f.authCalls++
	if f.authErr != nil || f.revokeRead && f.authCalls > 1 || caseID != f.authority.CaseID || artifactID != f.authority.ArtifactID {
		return value.HTTPHeaderReadAuthority{}, errors.Join(value.ErrUnavailable, f.authErr)
	}
	return f.authority, nil
}

func (f *headerFixture) ReadHTTPHeaderPage(_ context.Context, a value.HTTPHeaderReadAuthority, s value.HTTPHeaderSelection) (value.HTTPHeaderPage, error) {
	if a.ArtifactID != f.authority.ArtifactID {
		return value.HTTPHeaderPage{}, value.ErrUnavailable
	}
	return httpheaders.ReadPage(f.native, httpheaders.DefaultLimits(), artifact.HTTPHeadersNativeLimit, s)
}

// headerDocument is a synthetic stored projection of n exchanges with the
// given Content-Type value; every fourth record is partial.
func headerDocument(t *testing.T, n int, contentType string) []byte {
	t.Helper()
	l := httpheaders.DefaultLimits()
	start := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	pr := httpheaders.Projection{Format: artifact.HTTPHeadersFormat, Protocol: "http1", StartedAt: start, EndedAt: start.Add(time.Hour),
		Limits:  httpheaders.LimitsRecord{MaxFlows: l.MaxFlows, MaxHeaderBytes: l.MaxHeaderBytes, MaxFlowBytes: l.MaxFlowBytes, MaxTotalBytes: l.MaxTotalBytes, IdleTimeoutSeconds: int64(l.IdleTimeout / time.Second), Snaplen: httpheaders.Snaplen},
		Records: []httpheaders.Record{}}
	for i := range n {
		r := httpheaders.Record{Timestamp: start.Add(time.Duration(i) * time.Millisecond), Method: "GET", Status: 503, Headers: []httpheaders.Header{{Name: "content-type", Value: contentType}, {Name: "content-length", Value: "64"}}}
		if i%4 == 3 {
			r = httpheaders.Record{Timestamp: r.Timestamp, Method: "POST", Headers: []httpheaders.Header{}, Partial: true}
			pr.Counters.PartialRecords++
		}
		pr.Records = append(pr.Records, r)
	}
	pr.Counters.Records = uint64(n)
	pr.Counters.StoppedMidstream = 1
	b, err := pr.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newHeaderFixture(t *testing.T, n int, contentType string) (*headerFixture, *HTTPHeaderOperations) {
	t.Helper()
	now := time.Now().UTC()
	f := &headerFixture{now: now, scopes: []string{"evidence:read"}, native: headerDocument(t, n, contentType)}
	f.authority = value.HTTPHeaderReadAuthority{CaseID: headerCase, ArtifactID: headerArtifact, CaptureID: headerCapture,
		NativeType: artifact.HTTPHeadersArtifact, Format: artifact.HTTPHeadersFormat, DataClass: "extract", Version: artifact.Digest{9},
		Principal: headerPrincipal, AccessUntil: now.Add(time.Hour), ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	clock := func() time.Time { return f.now }
	s, err := NewHTTPHeaderOperations("https://asservat.example.invalid", clock, func() string { return headerRequest }, analysisapp.HTTPHeaderReads{Authority: f, Pages: f, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	return f, s
}

type headerReply struct {
	DataClass  string          `json:"data_class"`
	Status     string          `json:"status"`
	Data       json.RawMessage `json:"data"`
	NextCursor *string         `json:"next_cursor"`
	Warnings   []string        `json:"warnings"`
	Provenance []struct {
		ArtifactID string `json:"artifactID"`
		Digest     string `json:"digest"`
	} `json:"provenance"`
}
type headerPage struct {
	ProjectionDigest string `json:"projection_digest"`
	Records          []struct {
		Timestamp time.Time `json:"timestamp"`
		Status    int       `json:"status"`
		Partial   bool      `json:"partial"`
	} `json:"records"`
	DroppedFlows int      `json:"dropped_flows"`
	CoverageGaps []string `json:"coverage_gaps"`
	Code         string   `json:"code"`
}

func headerInput(cursor string, limit int) json.RawMessage {
	in := map[string]any{"case_id": headerCase, "artifact_id": headerArtifact}
	if cursor != "" {
		in["cursor"] = cursor
	}
	if limit != 0 {
		in["limit"] = limit
	}
	b, _ := json.Marshal(in)
	return b
}

func headerCall(t *testing.T, s *HTTPHeaderOperations, f *headerFixture, raw json.RawMessage) (headerReply, headerPage, OperationReply) {
	t.Helper()
	f.authCalls = 0
	reply, err := s.CallWithContext(context.Background(), f, OperationCall{requestID: headerRequest}, "get_http_headers", raw)
	if err != nil {
		t.Fatal(err)
	}
	var out headerReply
	var page headerPage
	if json.Unmarshal(reply.Body, &out) != nil || json.Unmarshal(out.Data, &page) != nil {
		t.Fatal(string(reply.Body))
	}
	return out, page, reply
}

func TestGetHTTPHeadersPagesTheApprovedProjection(t *testing.T) {
	f, s := newHeaderFixture(t, 230, "application/json")
	digest := artifact.Digest(sha256.Sum256(f.native))
	out, page, reply := headerCall(t, s, f, headerInput("", 0))
	if out.Status != "ok" || out.DataClass != "extract" || len(page.Records) != 100 || out.NextCursor == nil || *out.NextCursor != value.HTTPHeaderCursor(100, digest) {
		t.Fatalf("first page %+v %d", out, len(page.Records))
	}
	if page.ProjectionDigest != hash(digest) || page.DroppedFlows != 1 || len(page.CoverageGaps) != 1 || len(out.Warnings) != 1 || !strings.HasPrefix(out.Warnings[0], "SensitiveDataHandling") {
		t.Fatalf("gaps/handling %+v %+v", page, out.Warnings)
	}
	if len(out.Provenance) != 1 || out.Provenance[0].ArtifactID != headerArtifact || out.Provenance[0].Digest != hash(artifact.Digest{9}) {
		t.Fatalf("provenance %+v", out.Provenance)
	}
	// The reply inherits the evidence-access, authority and identity bounds.
	if reply.ValidUntil.After(f.authority.ValidUntil) || reply.auditDecision != operationAuditDecision(0) {
		t.Fatal("reply bound", reply.ValidUntil)
	}
	if f.authCalls != 2 {
		t.Fatal("authority rechecked after the read", f.authCalls)
	}
	// Walking with cursors delivers every record exactly once, in order.
	seen := len(page.Records)
	last := page.Records[len(page.Records)-1].Timestamp
	for cursor := *out.NextCursor; cursor != ""; {
		out, page, _ = headerCall(t, s, f, headerInput(cursor, 0))
		if out.Status != "ok" || len(page.Records) == 0 || !page.Records[0].Timestamp.After(last) {
			t.Fatalf("page at %s: %+v", cursor, out)
		}
		seen += len(page.Records)
		last = page.Records[len(page.Records)-1].Timestamp
		cursor = ""
		if out.NextCursor != nil {
			cursor = *out.NextCursor
		}
	}
	if seen != 230 {
		t.Fatal("walked", seen)
	}
	// An explicit limit is exact; partial records carry no status.
	out, page, _ = headerCall(t, s, f, headerInput("", 4))
	if len(page.Records) != 4 || !page.Records[3].Partial || page.Records[3].Status != 0 || *out.NextCursor != value.HTTPHeaderCursor(4, digest) {
		t.Fatalf("limit 4: %+v", page.Records)
	}
	// Limits outside 1..100 and unknown fields are invalid input.
	for _, raw := range []json.RawMessage{headerInput("", 101), json.RawMessage(`{"case_id":"` + headerCase + `","artifact_id":"` + headerArtifact + `","limit":0}`),
		json.RawMessage(`{"case_id":"` + headerCase + `","artifact_id":"` + headerArtifact + `","body":true}`)} {
		if _, err := s.CallWithContext(context.Background(), f, OperationCall{requestID: headerRequest}, "get_http_headers", raw); !errors.Is(err, contracts.ErrInvestigationWire) {
			t.Fatal(string(raw), err)
		}
	}
}

func TestGetHTTPHeadersFitsTheResponseLimitWithoutSkipping(t *testing.T) {
	long := strings.Repeat("a", 64) + "/" + strings.Repeat("b", 64) + "; charset=iso-8859-15"
	f, s := newHeaderFixture(t, 100, long)
	out, page, reply := headerCall(t, s, f, headerInput("", 100))
	if out.Status != "ok" || len(page.Records) == 0 || len(page.Records) >= 100 || len(reply.Body) > contracts.InvestigationOutputLimit {
		t.Fatalf("%d records in %d bytes", len(page.Records), len(reply.Body))
	}
	seen := len(page.Records)
	for out.NextCursor != nil {
		out, page, _ = headerCall(t, s, f, headerInput(*out.NextCursor, 100))
		seen += len(page.Records)
	}
	if seen != 100 {
		t.Fatal("walked", seen)
	}
}

func TestGetHTTPHeadersRefusals(t *testing.T) {
	notAvailable := func(t *testing.T, f *headerFixture, s *HTTPHeaderOperations, raw json.RawMessage) {
		t.Helper()
		out, page, reply := headerCall(t, s, f, raw)
		if out.Status != "error" || page.Code != "NotAvailable" || len(out.Provenance) != 0 || len(page.Records) != 0 || reply.auditDecision != operationAuditDenied {
			t.Fatalf("%+v %s", out, out.Data)
		}
	}
	for name, mutate := range map[string]func(*headerFixture){
		"no read rights":      func(f *headerFixture) { f.authErr = errors.New("synthetic deny") },
		"revoked during read": func(f *headerFixture) { f.revokeRead = true },
		"metadata artifact": func(f *headerFixture) {
			f.authority.NativeType, f.authority.DataClass = artifact.PCAPNGArtifact, "metadata"
		},
		"raw artifact": func(f *headerFixture) {
			f.authority.NativeType, f.authority.DataClass = artifact.RawPCAPNGArtifact, "raw"
		},
		"httpHeaders not extract": func(f *headerFixture) { f.authority.DataClass = "raw" },
		"access ended":            func(f *headerFixture) { f.authority.AccessUntil = f.now },
		"other principal":         func(f *headerFixture) { f.authority.Principal.Subject = "someone-else" },
		"tampered projection": func(f *headerFixture) {
			f.native = []byte(strings.Replace(string(f.native), `"content-length","value":"64"`, `"set-cookie","value":"s=1"`, 1))
		},
		"other artifact": func(f *headerFixture) { f.authority.ArtifactID = headerCapture },
	} {
		t.Run(name, func(t *testing.T) {
			f, s := newHeaderFixture(t, 10, "application/json")
			mutate(f)
			notAvailable(t, f, s, headerInput("", 0))
		})
	}
	// Missing evidence:read is denied before any lookup.
	f, s := newHeaderFixture(t, 10, "application/json")
	f.scopes = []string{"evidence:download"}
	if _, err := s.CallWithContext(context.Background(), f, OperationCall{requestID: headerRequest}, "get_http_headers", headerInput("", 0)); !errors.Is(err, identity.ErrDenied) || f.authCalls != 0 {
		t.Fatal("scope", err)
	}
	// Cursors: malformed, foreign or beyond the end are InvalidCursor.
	f, s = newHeaderFixture(t, 10, "application/json")
	digest := artifact.Digest(sha256.Sum256(f.native))
	other := digest
	other[1] ^= 1
	for _, cursor := range []string{"x", "0:" + strings.Repeat("0", 32), "05:" + hash(digest)[:32], value.HTTPHeaderCursor(3, other), value.HTTPHeaderCursor(10, digest)} {
		out, page, reply := headerCall(t, s, f, headerInput(cursor, 0))
		if out.Status != "error" || page.Code != "InvalidCursor" || reply.auditDecision != operationAuditInvalid {
			t.Fatalf("cursor %q: %s", cursor, out.Data)
		}
	}
	// Without read rights a cursor is not judged: no existence oracle.
	f.authErr = errors.New("synthetic deny")
	if _, page, _ := headerCall(t, s, f, headerInput(value.HTTPHeaderCursor(3, other), 0)); page.Code != "NotAvailable" {
		t.Fatal("cursor oracle", page.Code)
	}
}

func TestGetHTTPHeadersRoutingAndAuditInput(t *testing.T) {
	f, s := newHeaderFixture(t, 3, "text/plain")
	base := &InvestigationOperations{origin: s.PublicOrigin(), routes: map[string]Operations{}}
	ops, err := NewInvestigationHTTPHeaderOperations(base, s)
	if err != nil || len(ops.ToolNames()) != 1 || ops.ToolNames()[0] != "get_http_headers" {
		t.Fatal(err, ops.ToolNames())
	}
	if _, ok := base.Tool("get_http_headers"); ok {
		t.Fatal("a contract alone advertised the tool")
	}
	reply, err := ops.CallWithContext(context.Background(), f, OperationCall{requestID: headerRequest}, "get_http_headers", headerInput("", 2))
	if err != nil || !strings.Contains(string(reply.Body), `"status":"ok"`) {
		t.Fatal(err, string(reply.Body))
	}
	if _, err := NewInvestigationHTTPHeaderOperations(ops, s); err == nil {
		t.Fatal("duplicate registration")
	}
	// The audited input digest covers cursor and limit as supplied.
	wire, _ := contracts.NewInvestigationContracts()
	audited := &AuditedOperations{contracts: wire}
	a, err := audited.normalize("get_http_headers", headerInput("7:"+strings.Repeat("a", 32), 5))
	b, err2 := audited.normalize("get_http_headers", headerInput("", 5))
	if err != nil || err2 != nil || string(a) == string(b) || !strings.Contains(string(a), `"cursor":"7:`) {
		t.Fatal(string(a), string(b), err, err2)
	}
}
