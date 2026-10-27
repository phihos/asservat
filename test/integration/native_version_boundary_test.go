package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"testing"
	"time"
)

// Invalid/oversized helper input cannot echo a credential marker or select an
// administrator connection. These are test-process boundaries, not product auth.
func TestNativeActualVersionHelperInputBoundary(t *testing.T) {
	manifest := nativeVersionManifestFor(t)
	for version, binary := range manifest.Binaries {
		for _, kind := range []string{"unknown-field", "oversized", "wrong-role"} {
			t.Run(version+"/"+kind, func(t *testing.T) {
				marker := "synthetic-credential-must-not-appear"
				raw := []byte(`{"Unknown":"` + marker + `"}`)
				if kind == "oversized" {
					raw = bytes.Repeat([]byte(marker), (256<<10)/len(marker)+2)
				}
				if kind == "wrong-role" {
					raw, _ = json.Marshal(nativeVersionInput{Action: "claim", Postgres: "postgres://postgres:" + marker + "@127.0.0.1:1/custody_test?sslmode=disable"})
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, binary.Path)
				command.Stdin = bytes.NewReader(raw)
				var stdout nativeVersionBoundedOutput
				command.Stdout = &stdout
				command.Stderr = io.Discard
				err := command.Run()
				var out nativeVersionOutput
				if stdout.overflow || json.Unmarshal(stdout.Bytes(), &out) != nil || out.Accepted || bytes.Contains(stdout.Bytes(), []byte(marker)) {
					t.Fatal("invalid helper input escaped closed refusal")
				}
				want := "input"
				if kind == "wrong-role" {
					want = "pool"
					if err != nil {
						t.Fatal("wrong-role check did not complete")
					}
				} else if err == nil {
					t.Fatal("invalid framing was accepted")
				}
				if out.Stage != want || out.ErrorClass != "invalid" {
					t.Fatal("invalid input reached an operation", out.Stage, out.ErrorClass)
				}
			})
		}
	}
}
