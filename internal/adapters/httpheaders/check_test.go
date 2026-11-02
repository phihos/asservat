package httpheaders

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// validProjection is the projection of one synthetic exchange whose
// request and response carry secrets in fields the projection drops.
func validProjection(t *testing.T) (Projection, []byte) {
	t.Helper()
	f := newFeeder(t, DefaultLimits())
	c := newConn(40100)
	f.addGroups(c.handshake(), c.data(true, []byte(secretRequest), 7, 30), c.data(false, []byte(secretResponse), 20, 40))
	f.add(c.fin(true), c.fin(false))
	pr, _, b := f.close(t)
	if len(pr.Records) != 1 {
		t.Fatalf("fixture records %d", len(pr.Records))
	}
	return pr, b
}

func encode(t *testing.T, pr Projection) []byte {
	t.Helper()
	b, err := pr.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckProjectionAcceptsProducedDocument(t *testing.T) {
	_, b := validProjection(t)
	n, err := CheckProjection(bytes.NewReader(b), DefaultLimits(), int64(len(b)))
	if err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	c := NewProjectionCheck(DefaultLimits(), artifact.HTTPHeadersNativeLimit)
	for _, chunk := range [][]byte{b[:10], b[10:100], b[100:]} {
		if err := c.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// An empty capture is a valid projection too.
	p, _ := NewProjector(DefaultLimits(), t0)
	empty, _ := p.Close(t0.Add(time.Second), 0)
	if n, err := CheckProjection(bytes.NewReader(encode(t, empty)), DefaultLimits(), 1<<20); err != nil || n != 0 {
		t.Fatalf("empty: %d %v", n, err)
	}
}

func TestCheckProjectionRejects(t *testing.T) {
	pr, b := validProjection(t)
	mutate := func(m func(*Projection)) []byte {
		c := pr
		c.Records = append([]Record(nil), pr.Records...)
		for i := range c.Records {
			c.Records[i].Headers = append([]Header(nil), pr.Records[i].Headers...)
		}
		m(&c)
		return encode(t, c)
	}
	cases := map[string][]byte{
		"unapproved header":   mutate(func(p *Projection) { p.Records[0].Headers = append(p.Records[0].Headers, Header{"set-cookie", "s=1"}) }),
		"authorization":       mutate(func(p *Projection) { p.Records[0].Headers = []Header{{"authorization", "Bearer " + secret}} }),
		"secret parameter":    mutate(func(p *Projection) { p.Records[0].Headers[0].Value = "application/json; boundary=" + secret }),
		"secret charset":      mutate(func(p *Projection) { p.Records[0].Headers[0].Value = "text/plain; charset=" + strings.ToLower(secret) }),
		"bad length":          mutate(func(p *Projection) { p.Records[0].Headers[1].Value = "12 " + secret }),
		"header order":        mutate(func(p *Projection) { h := p.Records[0].Headers; h[0], h[1] = h[1], h[0] }),
		"duplicate header":    mutate(func(p *Projection) { p.Records[0].Headers = append(p.Records[0].Headers, p.Records[0].Headers[1]) }),
		"method":              mutate(func(p *Projection) { p.Records[0].Method = "BREW" }),
		"status":              mutate(func(p *Projection) { p.Records[0].Status = 0 }),
		"time before start":   mutate(func(p *Projection) { p.Records[0].Timestamp = p.StartedAt.Add(-time.Second) }),
		"time after end":      mutate(func(p *Projection) { p.Records[0].Timestamp = p.EndedAt.Add(time.Second) }),
		"format":              mutate(func(p *Projection) { p.Format = "other/v1" }),
		"limits":              mutate(func(p *Projection) { p.Limits.MaxFlows-- }),
		"record counter":      mutate(func(p *Projection) { p.Counters.Records++ }),
		"partial counter":     mutate(func(p *Projection) { p.Counters.PartialRecords++ }),
		"unknown field":       bytes.Replace(b, []byte(`{"format"`), []byte(`{"url":"/orders/`+secret+`","format"`), 1),
		"unknown record key":  bytes.Replace(b, []byte(`"partial":false`), []byte(`"partial":false,"host":"x"`), 1),
		"duplicate key":       bytes.Replace(b, []byte(`{"name":"content-type"`), []byte(`{"name":"x-`+secret+`","name":"content-type"`), 1),
		"whitespace":          append(append([]byte(nil), b...), ' '),
		"trailing document":   append(append([]byte(nil), b...), []byte(`{}`)...),
		"escaped equivalent":  bytes.Replace(b, []byte(`"format"`), []byte(`"form`+"\\"+`u0061t"`), 1),
		"not json":            []byte("GET / HTTP/1.1\r\n"),
		"empty":               nil,
		"oversized for limit": append(bytes.Repeat([]byte(" "), 4096), b...),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			limit := int64(len(b) + 1024)
			if name == "oversized for limit" {
				limit = int64(len(b))
			}
			if _, err := CheckProjection(bytes.NewReader(doc), DefaultLimits(), limit); err == nil {
				t.Fatalf("accepted %s", doc)
			}
		})
	}
	// Other accepted limits than the ones the document states.
	other := DefaultLimits()
	other.MaxFlows = 7
	if _, err := CheckProjection(bytes.NewReader(b), other, int64(len(b))); !errors.Is(err, ErrNotProjection) {
		t.Fatal("limits mismatch accepted", err)
	}
	if _, err := CheckProjection(bytes.NewReader(b), Limits{}, int64(len(b))); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid limits accepted", err)
	}
	c := NewProjectionCheck(DefaultLimits(), int64(len(b)-1))
	if err := c.Write(b); !errors.Is(err, artifact.ErrLimit) || !errors.Is(c.Close(), artifact.ErrLimit) {
		t.Fatal("streaming check exceeded its bound")
	}
}

func TestEncodeWithinDropsLatestRecords(t *testing.T) {
	f := newFeeder(t, DefaultLimits())
	for i := range 30 {
		c := newConn(uint16(41000 + i))
		f.addGroups(c.handshake(), c.data(true, []byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n")), c.data(false, []byte("HTTP/1.1 204 No Content\r\nContent-Type: text/plain\r\n\r\n")))
		f.add(c.fin(true), c.fin(false))
	}
	pr, _, full := f.close(t)
	if len(pr.Records) != 30 {
		t.Fatalf("records %d", len(pr.Records))
	}
	limit := int64(len(full) / 2)
	b, err := pr.EncodeWithin(limit)
	if err != nil || int64(len(b)) > limit {
		t.Fatalf("%d bytes: %v", len(b), err)
	}
	n, err := CheckProjection(bytes.NewReader(b), DefaultLimits(), limit)
	if err != nil || n == 0 || n >= 30 {
		t.Fatalf("%d %v", n, err)
	}
	var got Projection
	if err := json.Unmarshal(b, &got); err != nil || got.Counters.RecordsDropped != uint64(30-n) || !got.Records[n-1].Timestamp.Equal(pr.Records[n-1].Timestamp) {
		t.Fatalf("counters %+v %v", got.Counters, err)
	}
	if pr.Counters.RecordsDropped != 0 || len(pr.Records) != 30 {
		t.Fatal("EncodeWithin changed its receiver")
	}
	if b, err := pr.EncodeWithin(int64(len(full))); err != nil || !bytes.Equal(b, full) {
		t.Fatal("fitting projection changed", err)
	}
	if _, err := pr.EncodeWithin(64); !errors.Is(err, artifact.ErrLimit) {
		t.Fatal("envelope beyond the bound accepted", err)
	}
}
