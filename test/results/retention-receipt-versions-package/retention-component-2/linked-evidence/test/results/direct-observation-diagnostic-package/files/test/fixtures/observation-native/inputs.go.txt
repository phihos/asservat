//go:build ignore

// This executable belongs only to the owned native fixture image. Its supplied
// initial issuer/acceptance roots are synthetic test authority, not a product
// loader, installer receipt or runtime selector.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

const (
	inputFile       = "/fixture/input.json"
	controlSocket   = "/state/control.sock"
	joinedFile      = "/state/joined"
	maxInputBytes   = 512 << 10
	maxControlBytes = 64 << 10
)

var errFixture = errors.New("fixed observation fixture unavailable")

type fixtureAPI = API
type fixtureSQL = SQL
type fixtureAudit = Audit
type fixtureCA = CA
type fixtureInput = Input
type controlRequest = ControlRequest
type controlResult = ControlResult

func strictDecode(raw []byte, limit int, target any) error {
	if len(raw) == 0 || len(raw) > limit {
		return errFixture
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return errFixture
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errFixture
	}
	return nil
}

func loadInput(ctx context.Context, mode string) (fixtureInput, error) {
	var zero fixtureInput
	start := time.Now()
	nextReport := 30 * time.Second
	// Waiting for the one immutable test Secret is fixture setup only. It
	// creates no authority interval and performs no enrollment/effect retry.
	for {
		f, err := os.Open(inputFile)
		if err == nil {
			raw, read := io.ReadAll(io.LimitReader(f, maxInputBytes+1))
			closeErr := f.Close()
			defer clear(raw)
			var in fixtureInput
			if read != nil || closeErr != nil || strictDecode(raw, maxInputBytes, &in) != nil || in.Format != "observation-native-fixture/v1" || in.Mode != mode || in.PodUID == "" || in.PodUID != os.Getenv("POD_UID") || !in.Owner.Valid() || !in.Regional.Valid() || !in.Caller.Valid() || !time.Now().Before(in.Until) || in.Until.After(time.Now().Add(20*time.Minute)) {
				return zero, errFixture
			}
			return in, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return zero, errFixture
		}
		if elapsed := time.Since(start); elapsed >= nextReport && nextReport < 2*time.Minute {
			emitPhase("inputs-projection-missing", "wait", elapsed, nil)
			nextReport += 30 * time.Second
		}
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
