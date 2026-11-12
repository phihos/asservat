package providerconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	bao "github.com/openbao/openbao/api/v2"
)

// The applier's subset of both setup artifacts (worker and owner).
type setupArtifactPlan struct {
	Apply []struct {
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Body   json.RawMessage `json:"body"`
	} `json:"apply"`
	Inspect []string `json:"inspect"`
}

// setupApplyPath admits only the object kinds the artifacts create: ACL
// policies, auth roles, PKI roles and (ADR-184/193) transit keys. Every write
// is create-only. An outbox naming anything else, such as a mount, auth
// configuration or token, is refused before any write.
func setupApplyPath(p string) bool {
	parts := strings.Split(p, "/")
	ok := func(s string) bool { return providerName.MatchString(s) }
	switch {
	case len(parts) == 4 && parts[0] == "sys" && parts[1] == "policies" && parts[2] == "acl":
		return ok(parts[3])
	case len(parts) == 4 && parts[0] == "auth" && parts[2] == "role":
		return ok(parts[1]) && parts[1] != "token" && ok(parts[3])
	case len(parts) == 3 && (parts[1] == "roles" || parts[1] == "keys"):
		return ok(parts[0]) && parts[0] != "sys" && parts[0] != "auth" && ok(parts[2])
	}
	return false
}

// ApplySetupArtifact applies one ADR-183 outbox artifact with the operator's
// own administration client. It is create-only: an existing object is never
// overwritten, and the installer's own named readback decides whether it is
// exact. It then installs a read-only inspection policy over the artifact's
// named paths and returns one short-lived non-renewable inspection token.
func ApplySetupArtifact(ctx context.Context, client *bao.Client, name string, artifact []byte, out io.Writer) ([]byte, error) {
	return applySetupArtifact(ctx, client, name, artifact, out, false)
}

// BundledSetupInspectionRole is the one protected token role provisioned by the
// bundled provider's trusted setup. It is not an operator-selectable grant.
const BundledSetupInspectionRole = "asservat-inspection"

// ApplyBundledSetupArtifact uses the same create-only interpreter as the
// external operator path, but requests its inspection child through the fixed
// protected role. Unknown effects are not retried or redirected. The downstream
// SetupReader still independently verifies token and selected provider identity.
func ApplyBundledSetupArtifact(ctx context.Context, client *bao.Client, name string, artifact []byte, out io.Writer) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || client == nil {
		return nil, ErrSetupUnavailable
	}
	config := client.CloneConfig()
	config.Address = client.Address()
	config.MaxRetries = 0
	config.DisableRedirects = true
	config.DisableEnvironment = true
	isolated, err := bao.NewClient(config)
	if err != nil {
		return nil, ErrSetupUnavailable
	}
	isolated.SetToken(client.Token())
	isolated.SetHeaders(client.Headers().Clone())
	token, err := applySetupArtifact(ctx, isolated, name, artifact, out, true)
	if err != nil {
		return nil, ErrSetupUnavailable
	}
	return token, nil
}

func applySetupArtifact(ctx context.Context, client *bao.Client, name string, artifact []byte, out io.Writer, bundled bool) ([]byte, error) {
	var plan setupArtifactPlan
	if client == nil || out == nil || !providerName.MatchString(name) || json.Unmarshal(artifact, &plan) != nil || len(plan.Apply) == 0 || len(plan.Inspect) == 0 {
		return nil, ErrSetupUnavailable
	}
	for _, r := range plan.Apply {
		if r.Method != "POST" || !setupApplyPath(r.Path) || !json.Valid(r.Body) {
			return nil, ErrSetupUnavailable
		}
	}
	inspection, err := setupInspectionPolicy(plan.Inspect)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"policy": string(inspection)})
	if err != nil {
		return nil, ErrSetupUnavailable
	}
	writes := append(plan.Apply, struct {
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Body   json.RawMessage `json:"body"`
	}{"POST", "sys/policies/acl/" + name, body})
	for _, r := range writes {
		existing, e := client.Logical().ReadWithContext(ctx, r.Path)
		if e != nil {
			return nil, fmt.Errorf("read %s: %w", r.Path, e)
		}
		if existing != nil {
			_, _ = fmt.Fprintf(out, "exists, unchanged: %s\n", r.Path)
			continue
		}
		if _, e = client.Logical().WriteBytesWithContext(ctx, r.Path, bytes.Clone(r.Body)); e != nil {
			return nil, fmt.Errorf("create %s: %w", r.Path, e)
		}
		_, _ = fmt.Fprintf(out, "created: %s\n", r.Path)
	}
	request := &bao.TokenCreateRequest{Policies: []string{name}, NoDefaultPolicy: true, Renewable: new(bool), TTL: "10m", ExplicitMaxTTL: "10m", DisplayName: name}
	var secret *bao.Secret
	if bundled {
		request.Type = "service"
		secret, err = client.Auth().Token().CreateWithRoleWithContext(ctx, request, BundledSetupInspectionRole)
	} else {
		secret, err = client.Auth().Token().CreateWithContext(ctx, request)
	}
	if err != nil || secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, ErrSetupUnavailable
	}
	return []byte(secret.Auth.ClientToken), nil
}
