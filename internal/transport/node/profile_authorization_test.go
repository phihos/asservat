package node

import (
	"bytes"
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

func TestProfileAuthorizationDecoderIsReceiveOnlyAndClosed(t *testing.T) {
	work := maximumProfileTLSWork(t)
	work.Profile.AuthorizationRequired = true
	for _, mode := range []string{"current", "missing", "no-requirement", "plaintext", "bad-value", "oversize", "wrong-kind", "unavailable", "unavailable-and-value", "unavailable-no-requirement", "unavailable-plaintext", "unavailable-wrong-kind"} {
		t.Run(mode, func(t *testing.T) {
			wire := WireWork(work)
			wire.ProfileCapture.Authorization = []byte("Bearer private-wire-sentinel")
			switch mode {
			case "unavailable":
				wire.ProfileCapture.Authorization = nil
				wire.ProfileCapture.AuthorizationUnavailable = true
			case "unavailable-and-value":
				wire.ProfileCapture.AuthorizationUnavailable = true
			case "unavailable-no-requirement":
				wire.ProfileCapture.Authorization = nil
				wire.ProfileCapture.AuthorizationUnavailable = true
				wire.ProfileCapture.AuthorizationRequired = false
			case "unavailable-plaintext":
				wire.ProfileCapture.Authorization = nil
				wire.ProfileCapture.AuthorizationUnavailable = true
				wire.ProfileCapture.TLS = contracts.NodeProfileTLS{}
			case "unavailable-wrong-kind":
				wire.ProfileCapture.Authorization = nil
				wire.ProfileCapture.AuthorizationUnavailable = true
				wire.Kind = string(collector.WorkArmSource)
			case "missing":
				wire.ProfileCapture.Authorization = nil
			case "no-requirement":
				wire.ProfileCapture.AuthorizationRequired = false
			case "plaintext":
				wire.ProfileCapture.TLS = contracts.NodeProfileTLS{}
			case "bad-value":
				wire.ProfileCapture.Authorization = []byte("bad\nvalue")
			case "oversize":
				wire.ProfileCapture.Authorization = bytes.Repeat([]byte{'x'}, execution.GoProfileAuthorizationLimit+1)
			case "wrong-kind":
				wire.Kind = string(collector.WorkArmSource)
			}
			if len(wire.ProfileCapture.Authorization) > 0 || wire.ProfileCapture.AuthorizationUnavailable {
				if _, ok := DomainWork(wire); ok {
					t.Fatal("public queue decoder accepted private value")
				}
			}
			got, ok := ReceivedWork(wire)
			if (mode == "current" || mode == "unavailable") != ok {
				t.Fatal("private envelope accepted/refused wrong branch", mode)
			}
			if mode == "unavailable" && ok {
				public, _ := json.Marshal(got)
				if !got.ProfileAuthorizationUnavailable || len(got.ProfileAuthorization) != 0 || bytes.Contains(public, []byte("Unavailable")) || bytes.Contains(public, []byte("authorizationUnavailable")) {
					t.Fatal("receive-only refusal escaped into public queue")
				}
			}
			if ok && mode == "current" {
				wire.ProfileCapture.Authorization[0] = 'X'
				if string(got.ProfileAuthorization) != "Bearer private-wire-sentinel" {
					t.Fatal("received material aliases wire storage")
				}
				clear(got.ProfileAuthorization)
			}
		})
	}
}
