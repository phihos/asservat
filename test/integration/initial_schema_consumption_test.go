package integration

import (
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"os"
	"strings"
	"testing"
	"time"
)

// Fixture administrator injects only a mismatched original incarnation before
// any preparation effect, then restores the exact original journal. This tests
// the actual mounted constructor's enforcement, not a server restart or recovery.
func initialSchemaConstructorMismatch(t *testing.T, ctx context.Context, admin *pgxpool.Pool, api kubernetes.Interface, c contracts.InitialPreparer, files *os.Root) {
	t.Helper()
	rootAPI := api.CoreV1().ConfigMaps(c.Plan.BootstrapNamespace.Name)
	cm, err := rootAPI.Get(ctx, c.Plan.RootName, meta.GetOptions{})
	if err != nil {
		t.Fatal("schema fault fixture root unavailable")
	}
	original := cm.Data["root.json"]
	w, err := contracts.DecodeInitialPreparationRoot(strings.NewReader(original))
	if err != nil || w.Schema == nil || w.Schema.CompletedAt == nil {
		t.Fatal("completed schema fixture missing")
	}
	w.Schema.PostmasterAt = w.Schema.PostmasterAt.Add(-time.Second)
	raw, err := json.Marshal(w)
	if err != nil {
		t.Fatal("schema fault fixture encoding unavailable")
	}
	cm.Data["root.json"] = string(raw)
	if _, err = rootAPI.Update(ctx, cm, meta.UpdateOptions{}); err != nil {
		t.Fatal("schema fault injection unavailable")
	}
	restore := func() {
		t.Helper()
		current, e := rootAPI.Get(ctx, c.Plan.RootName, meta.GetOptions{})
		if e != nil {
			t.Fatal("schema fault cleanup read unavailable")
		}
		current.Data["root.json"] = original
		if _, e = rootAPI.Update(ctx, current, meta.UpdateOptions{}); e != nil {
			t.Fatal("schema fault cleanup unavailable")
		}
	}
	defer restore()
	t.Run("active-constructor-rejects-original-incarnation-mismatch", func(t *testing.T) {
		d, e := bootstrap.NewInitialPreparationDeployment(ctx, files)
		if d != nil {
			d.Close()
		}
		if !errors.Is(e, cfg.ErrChanged) || !strings.Contains(e.Error(), "initial preparation loader schema-completion:") {
			t.Fatal("active constructor did not reject at schema completion", e)
		}
		if _, e = api.CoreV1().Namespaces().Get(ctx, c.Plan.Workload.Namespace, meta.GetOptions{}); !apierrors.IsNotFound(e) {
			t.Fatal("constructor mismatch performed target declaration")
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM public.fleet_initial_activation)+(SELECT count(*) FROM public.fleet_trust)").Scan(&count); e != nil || count != 0 {
			t.Fatal("constructor mismatch created activation state")
		}
	})
}
