//go:build gadget && linux

package gadget

import (
	"bytes"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"testing"
)

type privateInputError struct{}

func (privateInputError) Error() string { panic("provider error rendered") }

// These invoke only the adapter logger, never initialize/run a collector.
func TestObservedEngineNotifiesPinnedInputGapsWithoutProviderText(t *testing.T) {
	var notices []InputNotice
	var out bytes.Buffer
	l := &lossLogger{level: logger.WarnLevel, w: &out, lines: 32, notice: func(n InputNotice) { notices = append(notices, n) }}
	logger.NewFromGenericLogger(l).Warnf("reading event: lost %d samples", uint64(3))
	logger.NewFromGenericLogger(l).Warnf("error reading event: %v", privateInputError{})
	logger.NewFromGenericLogger(l).Warnf("error processing event: %v", privateInputError{})
	if len(notices) != 3 || notices[0].LostSamples != 3 || notices[1].LostSamples != 0 || notices[2].LostSamples != 0 || l.lost.Load() != 3 || out.Len() != 0 {
		t.Fatal("missing loss/unknown notice", notices, l.lost.Load(), out.String())
	}
	// Similar text and zero losses create no fabricated input gap.
	logger.NewFromGenericLogger(l).Warnf("reading event: lost %d samples", uint64(0))
	logger.NewFromGenericLogger(l).Warnf("unrelated: %v", "error reading event: content")
	if len(notices) != 3 {
		t.Fatal("unrelated log classified as input gap")
	}
}

func TestOrdinaryEngineLogRetainsExistingBehavior(t *testing.T) {
	var out bytes.Buffer
	l := &lossLogger{level: logger.WarnLevel, w: &out}
	logger.NewFromGenericLogger(l).Warnf("reading event: lost %d samples", uint64(3))
	logger.NewFromGenericLogger(l).Warnf("error reading event: %v", "fixture failure")
	if l.lost.Load() != 3 || out.String() != "packet engine: error reading event: fixture failure\n" {
		t.Fatal(l.lost.Load(), out.String())
	}
}
