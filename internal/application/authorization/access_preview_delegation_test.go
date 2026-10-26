package authorization

import (
	"context"
	"errors"
	"testing"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

func (f *previewFixture) DecodePermissionSourceSpec([]byte) (cfg.Source, error) {
	return cfg.Source{}, cfg.ErrInvalid
}

// A configured delegation previewer who is not a fleet operator previews
// within their envelope; a change outside it is refused before any read, and
// a principal named by no envelope is refused.
func TestAccessPreviewDelegatedPreviewer(t *testing.T) {
	f, s := newPreviewFixture()
	f.caller.Groups = []string{"payments-leads"}
	envelope := cfg.PreviewEnvelope{Scope: cfg.Scope{ClusterID: previewCluster, Namespace: cfg.NamespaceRef{Name: "payments", UID: "ns"}}, Roles: []string{"evidence-reader"}, Issuers: []string{f.caller.Principal.Issuer}}
	s.Delegations = []PreviewDelegation{{Previewers: []PreviewPrincipal{{Issuer: f.caller.Principal.Issuer, Kind: "Group", ID: "payments-leads"}}, Envelope: envelope}}
	got, _, err := s.Preview(context.Background(), f, addDeny)
	if err != nil || got.DeltasTotal != 2 || got.Targets != 1 {
		t.Fatalf("within envelope: %v %+v", err, got)
	}
	s.Delegations[0].Envelope.Roles = []string{"workload-maintainer"}
	reads := len(f.reads)
	if _, _, err := s.Preview(context.Background(), f, addDeny); !errors.Is(err, cfg.ErrDenied) || len(f.reads) != reads {
		t.Fatalf("role outside envelope: %v", err)
	}
	s.Delegations[0].Previewers[0].ID = "someone-else"
	if _, _, err := s.Preview(context.Background(), f, addDeny); !errors.Is(err, identity.ErrDenied) {
		t.Fatalf("not a previewer: %v", err)
	}
	// Without fleet administration only delegation previewers exist.
	s.Administration = nil
	s.Delegations[0].Previewers[0].ID = "payments-leads"
	s.Delegations[0].Envelope.Roles = []string{"evidence-reader"}
	if _, _, err := s.Preview(context.Background(), f, addDeny); err != nil {
		t.Fatalf("delegation without fleet administration: %v", err)
	}
}
