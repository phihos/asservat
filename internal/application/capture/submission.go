package capture

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/capture"
)

type SubmissionTrustReader interface {
	SubmissionTrust(context.Context) (value.SubmissionTrust, error)
}
type PolicySubmissionSigner interface {
	SignPolicySubmission(context.Context, value.PolicySubmissionIntent) ([]byte, error)
}
type PolicySubmissionVerifier interface {
	VerifyPolicySubmission(context.Context, []byte, value.PolicySubmissionIntent) (value.SubmissionCheck, error)
}

// SignedPolicyAcceptor composes signature verification with the existing SQL
// current-source/delegation/recovery transaction. Expected scope and author are
// private compiler/authenticated-ingress inputs, never decoded from the JWS.
type SignedPolicyAcceptor struct {
	Verifier PolicySubmissionVerifier
	Store    PolicyAcceptor
	Now      func() time.Time
}

func (s SignedPolicyAcceptor) AcceptPolicySubmission(ctx context.Context, signed []byte, expected value.PolicySubmissionIntent, in value.PolicyAdmission) (value.AcceptedPolicy, error) {
	var zero value.AcceptedPolicy
	if s.Verifier == nil || s.Store == nil || s.Now == nil {
		return zero, value.ErrUnavailable
	}
	if !expected.Valid(s.Now()) || !in.Author.Valid(s.Now()) || expected.Actor != in.Author.Principal || expected.RootID != in.RootID || expected.InstallationID != in.Authority.InstallationID || expected.IssuerEpoch != in.Recovery.IssuerEpoch || expected.ScopeDigest != in.Authority.ScopeDigest || expected.Source.UID != in.Authority.PolicyUID {
		return zero, value.ErrDenied
	}
	verified, e := s.Verifier.VerifyPolicySubmission(ctx, signed, expected)
	if e != nil {
		return zero, e
	}
	in.Submission = verified.Submission
	in.Verification = verified
	if !in.Valid(s.Now()) {
		return zero, value.ErrDenied
	}
	// SQL repeats this proof's original deadline after every blocking phase.
	ctx, cancel := context.WithDeadline(ctx, verified.ValidUntil)
	defer cancel()
	return s.Store.AcceptPolicy(ctx, in)
}
