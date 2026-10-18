package browser

import (
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
)

func TestDownloadContentConfigurationNamesItsCheck(t *testing.T) {
	_, err := NewDownloadContentHandler(DownloadContentConfig{PublicOrigin: "https://asservat.example", Issuer: "https://id.example", MaxConcurrent: 0, MaxPerIdentity: 1, MaxDuration: time.Minute, Now: time.Now, NewID: func() string { return "" }}, SessionHandler{}, nil, nil, nil, nil, evidence.DownloadResponseTransfer{})
	var step interface{ FixedStep() string }
	if !errors.Is(err, ErrDownloadContentConfiguration) || !errors.As(err, &step) || step.FixedStep() != "content-config" {
		t.Fatal("configuration refusal lost its sentinel or its check", err)
	}
	_, err = NewDownloadContentHandler(DownloadContentConfig{PublicOrigin: "https://asservat.example", Issuer: "https://id.example", MaxConcurrent: 1, MaxPerIdentity: 1, MaxDuration: time.Minute, Now: time.Now, NewID: func() string { return "" }}, SessionHandler{}, nil, nil, nil, nil, evidence.DownloadResponseTransfer{})
	if !errors.Is(err, ErrDownloadContentConfiguration) || !errors.As(err, &step) || step.FixedStep() != "content-sessions" {
		t.Fatal("session refusal lost its sentinel or its check", err)
	}
}
