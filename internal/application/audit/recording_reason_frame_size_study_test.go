package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Study only: measure putting clear reason inside the already encrypted audit
// object's plaintext, while SQL would retain only a ciphertext reference.
// No real writer, decoder, SQL representation or digest protocol is changed.
func TestRecordingReasonOuterAuditFrameSizeStudy(t *testing.T) {
	in, _ := captureOperationFixture(t)
	c := *in.Capture
	c.Actor = authorization.PolicyPrincipal(c.RootID, strings.Repeat("p", 64))
	human := identity.Principal{Issuer: strings.Repeat("\"", 2048), Subject: strings.Repeat("\"", 256), ClientID: strings.Repeat("\"", 256), Kind: identity.Human}
	c.Initiator = &human
	d := artifact.Digest{}
	for i := range d {
		d[i] = 255
	}
	c.ScopeDigest = d
	c.SubmissionDigest = d
	c.ExpectationDigest = d
	c.Group = &value.CaptureGroupBinding{ParentCaptureID: c.RootID, SelectionDigest: d, ChildIndex: 15, ChildCount: 16}
	c.Target.NamespaceUID = strings.Repeat("\"", 64)
	c.Target.WorkloadUID = strings.Repeat("\"", 64)
	c.Target.PodUID = strings.Repeat("\"", 64)
	c.IdentityRevision = identity.Revision{UID: strings.Repeat("\"", 64), Generation: 2147483647, Digest: d}
	c.PermissionSequence = 9223372036854775807
	c.ReservedBytes = (16 << 20) - 1
	if !c.Valid() {
		t.Fatal("valid bounded capture required")
	}
	in.Capture = &c
	in.Actor = human
	raw, err := captureEncoding(in, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	var proposed map[string]any
	if err = json.Unmarshal(raw, &proposed); err != nil {
		t.Fatal(err)
	}
	proposed["Reason"] = strings.Repeat("\U0001f642", 512)
	// Conservative small reference from the study's measured capture delta.
	proposed["ReasonRef"] = strings.Repeat("r", 238)
	withBody, err := captureEncoding(proposed, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	_, err = captureEncoding(proposed, 16<<10)
	t.Logf("max_escape_heavy_operation_baseline=%d outer_plain_reason_candidate=%d intent_cap=16384 fits=%t; ciphertext envelope not counted here", len(raw), len(withBody), err == nil)
}
