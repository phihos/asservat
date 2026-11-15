package capture

import (
	"bytes"
	"context"
	"strings"
	"testing"

	value "asservat.local/asservat/internal/domain/capture"
)

func TestRecordingReasonPreviewPreservesScopeAndLifetime(t *testing.T) {
	for _, n := range []int{2, 16} {
		p := recordingGroupSizePreview(t, n)
		scope := bytes.Clone(p.CanonicalScope)
		digest := p.ScopeDigest
		deadline, review := p.Deadline, p.SelectionUntil
		text := " \n" + strings.Repeat("\U0001f642", 509) + " " // 512 scalars, whitespace kept
		if err := (ContextInvestigation{}).preparePreviewReason(context.Background(), &p, &text); err != nil {
			t.Fatal(err)
		}
		if !ValidContextPreview(p) || p.Intent.Reason == nil || *p.Intent.Reason != text {
			t.Fatal("reason not recorded")
		}
		if p.ScopeDigest != digest || !bytes.Equal(p.CanonicalScope, scope) || !p.Deadline.Equal(deadline) || !p.SelectionUntil.Equal(review) {
			t.Fatal("descriptive reason changed collection/grant/review scope")
		}
		if err := (ContextInvestigation{}).preparePreviewReason(context.Background(), &p, &text); err == nil {
			t.Fatal("same preview replaced its reason")
		}
	}
}

func TestRecordingReasonInputBounds(t *testing.T) {
	for _, text := range []string{"", strings.Repeat("x", 513), string([]byte{255})} {
		p := recordingGroupSizePreview(t, 2)
		if err := (ContextInvestigation{}).preparePreviewReason(context.Background(), &p, &text); err != value.ErrInvalid || p.Intent.Reason != nil {
			t.Fatal("invalid text accepted", err)
		}
	}
	p := recordingGroupSizePreview(t, 2)
	if err := (ContextInvestigation{}).preparePreviewReason(context.Background(), &p, nil); err != nil || p.Intent.Reason != nil {
		t.Fatal("absent reason changed the preview")
	}
}
