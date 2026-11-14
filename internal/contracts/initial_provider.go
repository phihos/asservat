package contracts

import (
	"time"
)

// Explicit protected installation input, never inferred from a token or endpoint.
// Policies use the finite JSON ACL profile validated by the provider adapter.
type InitialProviderProfile struct {
	Format       string                `json:"format"`
	Material     WorkerObjectReference `json:"material"`
	IssuerPolicy string                `json:"issuerPolicy"`
	WrapRole     string                `json:"wrapRole"`
	WrapPolicy   string                `json:"wrapPolicy"`
	UnwrapRole   string                `json:"unwrapRole"`
	UnwrapPolicy string                `json:"unwrapPolicy"`
}

// Original provider-issued identity and hard end, retained independently of each
// request deadline. No token or secret-payload digest belongs in the public root.
type InitialProviderParent struct {
	Accessor  string    `json:"accessor"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type InitialProviderResponse struct {
	Token     string    `json:"token"`
	Accessor  string    `json:"accessor"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}
