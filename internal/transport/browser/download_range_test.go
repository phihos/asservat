package browser

import (
	"errors"
	"net/http"
	"testing"
)

func TestNativeRange(t *testing.T) {
	for _, tc := range []struct {
		name, rng, match, ifRange string
		size, offset, length      int64
		partial                   bool
		err                       error
	}{
		{name: "full", size: 100, length: 100},
		{name: "empty", size: 0},
		{name: "one byte", size: 100, rng: "bytes=0-0", length: 1, partial: true},
		{name: "open", size: 100, rng: "bytes=90-", offset: 90, length: 10, partial: true},
		{name: "suffix", size: 100, rng: "bytes=-10", offset: 90, length: 10, partial: true},
		{name: "clamp suffix", size: 100, rng: "bytes=-200", length: 100, partial: true},
		{name: "clamp end", size: 100, rng: "bytes=90-99999999", offset: 90, length: 10, partial: true},
		{name: "resume", size: 100, rng: "bytes=50-", match: `"v1"`, offset: 50, length: 50, partial: true},
		{name: "etag list", size: 100, match: `W/"v1", "other,tag", "v1"`, length: 100},
		{name: "wildcard", size: 100, match: "*", length: 100},
		{name: "wrong match", size: 100, match: `"v2"`, err: errPrecondition},
		{name: "weak match", size: 100, match: `W/"v1"`, err: errPrecondition},
		{name: "bad match", size: 100, match: `"v1" garbage`, err: errConditional},
		{name: "bad wildcard", size: 100, match: `*, "v1"`, err: errConditional},
		{name: "if range equal", size: 100, rng: "bytes=50-", ifRange: `"v1"`, offset: 50, length: 50, partial: true},
		{name: "if range different full", size: 100, rng: "bytes=50-", ifRange: `"v2"`, length: 100},
		{name: "if range weak full", size: 100, rng: "bytes=50-", ifRange: `W/"v1"`, length: 100},
		{name: "if range date full", size: 100, rng: "bytes=50-", ifRange: "Wed, 21 Oct 2015 07:28:00 GMT", length: 100},
		{name: "if range ignores malformed range", size: 100, rng: "bad", ifRange: `"v2"`, length: 100},
		{name: "if match takes precedence", size: 100, rng: "bytes=50-", match: `"v2"`, ifRange: `"v2"`, err: errPrecondition},
		{name: "range empty file", size: 0, rng: "bytes=0-", err: errRange},
		{name: "past end", size: 100, rng: "bytes=100-", err: errRange},
		{name: "backward", size: 100, rng: "bytes=10-5", err: errRange},
		{name: "zero suffix", size: 100, rng: "bytes=-0", err: errRange},
		{name: "negative", size: 100, rng: "bytes=-1-2", err: errRange},
		{name: "overflow", size: 100, rng: "bytes=0-9223372036854775808", err: errRange},
		{name: "multipart", size: 100, rng: "bytes=0-2,5-7", err: errRange},
		{name: "unsupported unit full response", size: 100, rng: "items=0-1", length: 100},
		{name: "signed", size: 100, rng: "bytes=+0-1", err: errRange},
		{name: "internal whitespace", size: 100, rng: "bytes=0 - 1", err: errRange},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := selectNativeRange(tc.size, `"v1"`, tc.rng, tc.match, tc.ifRange)
			if !errors.Is(err, tc.err) {
				t.Fatalf("error %v, want %v", err, tc.err)
			}
			if err == nil && (r.Offset != tc.offset || r.Length != tc.length || r.Partial != tc.partial) {
				t.Fatalf("range %+v", r)
			}
		})
	}
}

func TestNativeConditionalPrecedenceAndHeaderLimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers http.Header
		status  int
	}{
		{"weak cache validator", http.Header{"If-None-Match": {`W/"v1"`}}, 304},
		{"wildcard cache validator", http.Header{"If-None-Match": {"*"}}, 304},
		{"If-Match before cache validator", http.Header{"If-Match": {`"v2"`}, "If-None-Match": {`"v1"`}}, 412},
		{"validator before range", http.Header{"If-None-Match": {`"v1"`}, "Range": {"bad"}}, 304},
		{"empty present match", http.Header{"If-Match": {""}}, 412},
		{"multiline match", http.Header{"If-Match": {`"v2"`, `"v1"`}}, 0},
		{"empty list members", http.Header{"If-Match": {`, "v1", ,`}}, 0},
		{"multiline If-Range", http.Header{"If-Range": {`"v1"`, `"v1"`}}, 400},
		{"multiline Range", http.Header{"Range": {"bytes=0-1", "bytes=3-4"}}, 416},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveDownloadSelection(100, `"v1"`, tc.headers)
			if tc.status == 0 && err != nil || tc.status != 0 && (err == nil || DownloadConditionStatus(err) != tc.status) {
				t.Fatal(err)
			}
		})
	}
}

func FuzzNativeRange(f *testing.F) {
	for _, s := range []string{"bytes=0-1", "bytes=-1", "bytes=9223372036854775808-", "bytes=0-1,2-3"} {
		f.Add(s, "", "")
	}
	f.Fuzz(func(t *testing.T, r, m, i string) {
		got, err := selectNativeRange(100, `"v1"`, r, m, i)
		if err == nil && (got.Offset < 0 || got.Length < 1 || got.Offset+got.Length > 100) {
			t.Fatalf("out of bounds %+v", got)
		}
	})
}
