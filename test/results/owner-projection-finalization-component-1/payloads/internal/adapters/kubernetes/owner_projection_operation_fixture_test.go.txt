package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ownerProjectionOperationFixture struct {
	*ownerIdentityOperationFixture
	provider      *ownerOperationProviderFixture
	roles         *ownerIdentityOperationSQLFixture
	verification  *ownerProjectionSQLFixture
	projection    *ProviderOwnerProjection
	creates       [2]atomic.Int32
	launches      atomic.Int32
	journalWrites atomic.Int32
	// Exact selected response failures only. The effect is either committed
	// then its response lost, or the original journal PUT never takes effect.
	lose        atomic.Int32 // 1 credentials CREATE, 2 configuration CREATE, 3 launch PUT, 4 journal PUT.
	dropJournal atomic.Bool
}

// The SQL portion is an explicit stand-in. All original native phases,
// concrete SetupReader HTTPS and original journal/object effects still run.
type ownerProjectionSQLFixture struct {
	roles                 *ownerIdentityOperationSQLFixture
	beforeCurrent         func()
	beforeEffect          func()
	beforeFinal           func()
	checks                int
	finalizations         int
	semanticVersion       int64
	beforeFinalizeCurrent func()
}

func (s *ownerProjectionSQLFixture) AdvanceOwnerProjectionOperation(ctx context.Context, op *OwnerProjectionOperation) (OwnerProjectionAdvance, error) {
	var zero OwnerProjectionAdvance
	if _, err := op.AdmittedOwnerIdentityRoles(ctx, s.roles.root); err != nil {
		return zero, err
	}
	if s.beforeCurrent != nil {
		s.beforeCurrent()
	}
	if op.OwnerProjectionExecutionOnly() {
		if err := op.BindOwnerProjectionSemanticVersion(ctx, s.roles.root, s.version()); err != nil {
			return zero, err
		}
	}
	current, err := op.ReadOwnerProjectionAfterLock(ctx, s.roles.root)
	if err != nil {
		return zero, err
	}
	for _, role := range current.State.Roles {
		if role.Claim == nil || role.Receipt == nil || s.roles.effects[role.Purpose] != role.Claim.OperationID {
			return zero, cfg.ErrUnavailable
		}
	}
	s.checks++
	if s.beforeEffect != nil {
		s.beforeEffect()
	}
	if err = op.ApplyOwnerProjection(ctx, s.roles.root); err != nil {
		return zero, err
	}
	if op.OwnerProjectionExecutionOnly() {
		return op.OwnerProjectionExecutionResult(ctx, s.roles.root)
	}
	if s.beforeFinal != nil {
		s.beforeFinal()
	}
	if _, err = op.ReadOwnerProjectionFinal(ctx, s.roles.root); err != nil {
		return zero, err
	}
	return op.OwnerProjectionResult(ctx, s.roles.root)
}

func newOwnerProjectionOperationFixture(t *testing.T) *ownerProjectionOperationFixture {
	t.Helper()
	return newOwnerProjectionOperationPreparedFixture(t, true)
}

func newOwnerProjectionOperationPreparedFixture(t *testing.T, completeRoles bool) *ownerProjectionOperationFixture {
	t.Helper()
	provider := newOwnerOperationProviderFixture(t)
	f := &ownerProjectionOperationFixture{ownerIdentityOperationFixture: newOwnerIdentityOperationProviderFixture(t, &provider.endpoint), provider: provider}
	startOwnerIdentityOperationAcceptedObserver(t, f.ownerIdentityOperationFixture)
	f.roles = &ownerIdentityOperationSQLFixture{root: f.root, effects: map[string]string{}}
	if completeRoles {
		if _, err := f.root.OpenProviderOwnerIdentityRoles(context.Background()); err != nil {
			t.Fatal("original role root", err)
		}
		for _, purpose := range contracts.OwnerIdentityRolePurposes() {
			pending, err := f.root.AdvanceProviderOwnerIdentityRole(context.Background(), purpose, f.roles)
			if err != nil || pending.Status != OwnerIdentityRoleAdvancePending {
				t.Fatal("original pending role", purpose, err)
			}
			complete, err := f.root.AdvanceProviderOwnerIdentityRole(context.Background(), purpose, f.roles)
			if err != nil || complete.Status != OwnerIdentityRoleAdvanceComplete {
				t.Fatal("original role acknowledgement", purpose, err)
			}
		}
	}
	in := provider.input(t, f.ownerIdentityOperationFixture)
	// This is explicit synthetic provider-owned material. The runtime verifies
	// its current original Secret, but this test makes no IAM/backend claim.
	f.api.mu.Lock()
	selected := in.ProviderAuthentication.AuditCredentials
	path := "/api/v1/namespaces/" + in.Namespace.Name + "/secrets/" + selected.Name
	raw, _ := json.Marshal(f.api.objects[path])
	var material core.Secret
	if json.Unmarshal(raw, &material) != nil {
		f.api.mu.Unlock()
		t.Fatal("selected material")
	}
	material.Data = map[string][]byte{contracts.OwnerProviderAuditCredentialFile: []byte(`{"accessKeyID":"synthetic-owner-audit","secretAccessKey":"synthetic-owner-key","sessionToken":""}`)}
	raw, _ = json.Marshal(material)
	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	f.api.objects[path] = object
	f.api.mu.Unlock()
	f.verification = &ownerProjectionSQLFixture{roles: f.roles}
	var err error
	f.projection, err = NewProviderOwnerProjection(f.root, f.verification, in, provider.reader)
	if err != nil {
		t.Fatal("explicit operation projection constructor", err)
	}
	f.installProjectionResponses(t)
	return f
}

func (f *ownerProjectionOperationFixture) installProjectionResponses(t *testing.T) {
	t.Helper()
	f.api.mu.Lock()
	defer f.api.mu.Unlock()
	previous := f.api.extra
	collection := "/api/v1/namespaces/" + f.resources.initial.Namespace.Name
	f.api.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Query().Get("dryRun") != "" {
			return previous(w, r)
		}
		journal := r.Method == http.MethodPut && r.URL.Path == f.resources.path()
		launch := r.Method == http.MethodPut && r.URL.Path == f.projection.projection.launchPath()
		create := r.Method == http.MethodPost && (r.URL.Path == collection+"/secrets" || r.URL.Path == collection+"/configmaps")
		if !journal && !launch && !create {
			return previous(w, r)
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
			return true
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var next map[string]any
		if json.Unmarshal(raw, &next) != nil {
			t.Error("fixture effect body")
			return true
		}
		metadata, ok := next["metadata"].(map[string]any)
		if !ok {
			t.Error("fixture effect metadata")
			return true
		}
		name, _ := metadata["name"].(string)
		purpose := int32(4)
		if create {
			if name == f.resources.names.OwnerProviders && r.URL.Path == collection+"/secrets" {
				purpose = 1
			} else if name == f.resources.names.OwnerInputs && r.URL.Path == collection+"/configmaps" {
				purpose = 2
			} else {
				return previous(w, r)
			}
		}
		if launch {
			purpose = 3
		}
		if r.URL.Query().Get("fieldValidation") != "Strict" {
			t.Error("effect omitted strict validation")
		}
		full := r.URL.Path
		if create {
			full += "/" + name
		}
		next["apiVersion"], next["kind"] = "v1", "Secret"
		if purpose == 2 {
			next["kind"] = "ConfigMap"
		}
		if launch {
			next["apiVersion"], next["kind"] = "apps/v1", "Deployment"
		}
		if journal {
			f.journalWrites.Add(1)
		}
		if journal && f.dropJournal.Swap(false) {
			w.WriteHeader(503)
			return true
		}
		if create {
			if f.api.objects[full] != nil {
				f.api.status(w, 409, meta.StatusReasonAlreadyExists, "objects", "")
				return true
			}
			f.creates[purpose-1].Add(1)
			encoded, _ := json.Marshal(next)
			f.api.store(full, encoded)
		} else {
			old := f.api.objects[full]
			if old == nil {
				t.Error("fixture CAS missing original")
				return true
			}
			om := old["metadata"].(map[string]any)
			if metadata["uid"] != om["uid"] || metadata["resourceVersion"] != om["resourceVersion"] {
				f.api.status(w, 409, meta.StatusReasonConflict, "objects", "")
				return true
			}
			f.api.serial++
			metadata["resourceVersion"] = strconv.Itoa(f.api.serial)
			if launch {
				metadata["generation"] = float64(2)
				f.launches.Add(1)
			}
			f.api.objects[full] = next
		}
		if f.lose.CompareAndSwap(purpose, 0) {
			w.WriteHeader(503)
			return true
		}
		if create {
			w.WriteHeader(http.StatusCreated)
		}
		permissionReply(w, f.api.objects[full])
		return true
	}
}

func (s *ownerProjectionSQLFixture) version() int64 {
	if s.semanticVersion == 0 {
		return 1
	}
	return s.semanticVersion
}
func (s *ownerProjectionSQLFixture) FinalizeOwnerProjectionOperation(ctx context.Context, f *OwnerProjectionFinalization) (OwnerProjectionAdvance, error) {
	var zero OwnerProjectionAdvance
	if _, _, err := f.AdmitOwnerProjectionFinalization(ctx, s.roles.root); err != nil {
		return zero, err
	}
	if err := f.MatchOwnerProjectionSemanticVersion(ctx, s.roles.root, s.version()); err != nil {
		return zero, err
	}
	first, err := f.ReadOwnerProjectionFinalizationAfterLock(ctx, s.roles.root)
	if err != nil {
		return zero, err
	}
	for _, role := range first.State.Roles {
		if role.Claim == nil || role.Receipt == nil || s.roles.effects[role.Purpose] != role.Claim.OperationID {
			return zero, cfg.ErrUnavailable
		}
	}
	s.finalizations++
	if s.beforeFinalizeCurrent != nil {
		s.beforeFinalizeCurrent()
	}
	if _, err = f.ReadOwnerProjectionFinalizationCurrent(ctx, s.roles.root); err != nil {
		return zero, err
	}
	return f.OwnerProjectionFinalizationResult(ctx, s.roles.root)
}
