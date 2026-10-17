package planning

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestHistoricalContextScopeIdentityRequiresExactCanonicalCompilerShape(t *testing.T) {
	in, now := contextInput(t)
	p, err := CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ReadContextScopeIdentity(p.CanonicalScope, p.ScopeDigest)
	if err != nil || s.Actor != in.Executor || s.Target != in.Target.Target() || s.CaptureID != in.CaptureID || !s.Deadline.Equal(in.Deadline) {
		t.Fatal("historical scope binding", err)
	}
	for name, change := range map[string]func([]byte) []byte{
		"unknown": func(b []byte) []byte { return append(b[:len(b)-1], []byte(`,"reason":"never accepted"}`)...) },
		"duplicate executor": func(b []byte) []byte {
			return append(b[:len(b)-1], []byte(`,"executor":{"issuer":"evil","subject":"attacker","clientID":"browser","identityType":"human"}}`)...)
		},
		"noncanonical": func(b []byte) []byte { return append(b, '\n') },
		"trailing":     func(b []byte) []byte { return append(b, []byte(`{}`)...) },
		"version": func(b []byte) []byte {
			return bytes.Replace(b, []byte("collection-scope/v1"), []byte("collection-scope/v2"), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := change(bytes.Clone(p.CanonicalScope))
			if _, err := ReadContextScopeIdentity(b, sha256.Sum256(b)); err == nil {
				t.Fatal("accepted altered scope")
			}
		})
	}
	if _, err := ReadContextScopeIdentity(p.CanonicalScope, artifact.Digest{1}); err == nil {
		t.Fatal("wrong immutable digest")
	}
}
