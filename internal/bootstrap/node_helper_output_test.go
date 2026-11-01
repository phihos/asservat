package bootstrap

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNodeHelperOutputCopyEnforcesLimit(t *testing.T) {
	for _, size := range []int{4096, 4097} {
		var output nodeHelperOutput
		// Hide WriterTo so io.Copy also exercises the destination's ReadFrom path.
		source := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", size))}
		_, err := io.Copy(&output, source)
		if (err == nil) != (size == 4096) || len(output.String()) > 4096 {
			t.Fatal("copy bypassed bounded helper output", size, len(output.String()), err != nil)
		}
	}
}

func TestNodeHelperOutputCommandEnforcesLimit(t *testing.T) {
	for _, mode := range []string{"small", "large"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNodeHelperOutputCommandChild$")
			cmd.Env = append(os.Environ(), "ASSERVAT_NODE_HELPER_OUTPUT_CHILD="+mode)
			var output nodeHelperOutput
			cmd.Stdout, cmd.Stderr = &output, io.Discard
			err := cmd.Run()
			if ctx.Err() != nil || (err == nil) != (mode == "small") || len(output.String()) > 4096 || (mode == "small" && len(output.String()) < 1024) {
				t.Fatal("command bypassed bounded helper output", len(output.String()), err != nil)
			}
		})
	}
}

func TestNodeHelperOutputCommandChild(t *testing.T) {
	mode := os.Getenv("ASSERVAT_NODE_HELPER_OUTPUT_CHILD")
	if mode == "" {
		t.Skip("owned output-bound helper only")
	}
	size := 1024
	if mode == "large" {
		size = 4097
	}
	if _, err := os.Stdout.Write(bytes.Repeat([]byte("x"), size)); err != nil {
		t.Fatal("synthetic helper write failed")
	}
}
