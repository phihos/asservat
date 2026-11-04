package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestProfileAuthorizationPrivateMapClosedAndBounded(t *testing.T) {
	a := RegionalProfileAuthorization{Format: RegionalProfileAuthorizationFormat, Entries: []RegionalProfileAuthorizationEntry{{Name: "pprof", Authorization: []byte("Bearer synthetic-private-sentinel")}}}
	b, _ := json.Marshal(a)
	got, err := DecodeRegionalProfileAuthorization(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Clear()
	if !bytes.Equal(got.Entries[0].Authorization, a.Entries[0].Authorization) {
		t.Fatal("header changed")
	}
	for _, text := range []string{fmt.Sprint(got), fmt.Sprintf("%#v", got), fmt.Sprint(got.Entries[0]), fmt.Sprintf("%#v", got.Entries[0])} {
		if strings.Contains(text, "sentinel") {
			t.Fatal("private value exposed in diagnostics")
		}
	}
	// A single header can exceed its own limit while the whole map still fits.
	oversized := a
	oversized.Entries = []RegionalProfileAuthorizationEntry{{Name: "pprof", Authorization: bytes.Repeat([]byte{'x'}, 4097)}}
	oversizedRaw, _ := json.Marshal(oversized)
	if len(oversizedRaw) >= RegionalProfileAuthorizationMaxBytes {
		t.Fatal("invalid oversized-header fixture")
	}
	if _, err := DecodeRegionalProfileAuthorization(bytes.NewReader(oversizedRaw)); err == nil {
		t.Fatal("wire decoder admitted oversized selected header")
	}
	for _, raw := range []string{string(b) + `{}`, strings.Replace(string(b), `"format":`, `"unknown":1,"format":`, 1), `{"format":"wrong","entries":[]}`, `{"format":"asservat-profile-authorization/v1","entries":[{"name":"pprof","authorization":"DQo="}]}`, strings.Repeat(" ", RegionalProfileAuthorizationMaxBytes+1)} {
		if _, err := DecodeRegionalProfileAuthorization(strings.NewReader(raw)); err == nil {
			t.Fatal("invalid private map accepted")
		}
	}
}

func TestProfileAuthorizationMaximumPrivateProjectionFits(t *testing.T) {
	a := RegionalProfileAuthorization{Format: RegionalProfileAuthorizationFormat}
	for n := 0; n < 64; n++ {
		a.Entries = append(a.Entries, RegionalProfileAuthorizationEntry{Name: fmt.Sprintf("endpoint-%054d", n), Authorization: bytes.Repeat([]byte{'x'}, 4096)})
	}
	raw, err := json.Marshal(a)
	if err != nil || len(raw) > RegionalProfileAuthorizationMaxBytes {
		t.Fatal("maximum supported private map exceeds fixed projection bound", len(raw), err)
	}
	decoded, err := DecodeRegionalProfileAuthorization(bytes.NewReader(raw))
	if err != nil || len(decoded.Entries) != 64 {
		t.Fatal("maximum supported map rejected", err)
	}
	decoded.Clear()
	t.Logf("maximum private map: %d encoded bytes; %d retained header bytes", len(raw), 64*4096)
}
