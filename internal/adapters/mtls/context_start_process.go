package mtls

import (
	"context"

	value "asservat.local/asservat/internal/domain/execution"
	fleet "asservat.local/asservat/internal/domain/fleet"
)

// ContextStartProcessReader returns the connector observation already verified
// inside this exact executor's complete native proof. The concrete producer
// must require the same process-owned credentials instance and preserve the
// proof's original interval, including its registration and closing source.
// It supplies no new observation from a cached DTO or caller-chosen identity.
// Readers without that composition retain the independent checks.
type ContextStartProcessReader interface {
	ReadAPIProcessConnector(context.Context, *ConnectorProcessCredentials) (value.APIProcessObservation, ConnectorProcessObservation, error)
}

// ContextStartProcessSetupReader opens one native setup bracket for the exact
// installed credentials instance. The producer retains the original proof,
// source, generation and earliest caller/proof cutoff. A failed Begin cannot
// fall back to an independent read or replace the original interval.
type ContextStartProcessSetupReader interface {
	BeginAPIContextSetup(context.Context, *ConnectorProcessCredentials) (ContextStartProcessSetup, error)
}

// ContextStartProcessSetup belongs to one context-start opening only. Reads
// check the same owned proof and current local credentials/generation without
// renewing it. Source returns the initial proof's actual closing source once.
// Finish, called once after Source and response headers, performs the complete
// closing native checks. Reads remain available for the final local check after
// the second owner authentication. Close cancels and joins all owned work; no
// method on the closed handle supplies authority to an exchange or later work.
type ContextStartProcessSetup interface {
	ContextStartProcessReader
	Source(context.Context) (fleet.ConnectorIdentitySource, error)
	Finish(context.Context) error
	Close()
}
