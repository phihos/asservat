package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	"k8s.io/client-go/rest"
)

// releaseRecord creates revision 1 of the ADR-227 release record in the hub
// namespace, as the runner, with the original image and this binary's schema.
func (k *InstallerContinuation) releaseRecord(ctx context.Context) error {
	r, err := contracts.NewReleaseRecord(k.plan.Plan.InstallationID, k.plan.Plan.Workload.Image, postgres.CompiledSchemaVersion)
	if err != nil {
		return err
	}
	return kube.CreateReleaseRecord(ctx, k.in.kubernetes("administrator-token"), k.plan.Plan.Workload.Namespace, r)
}

// ErrReleaseRefused is a refused release change: nothing was changed.
var ErrReleaseRefused = errors.New("release change refused")

// releaseSchema is the part of the upgrade migrator the image change uses.
type releaseSchema interface {
	State(context.Context) (postgres.SchemaState, error)
	PlannedFloor(postgres.SchemaState) (int64, error)
	Run(context.Context) (int64, int64, error)
}

// releaseChange is one ADR-227 image change of hub-worker and hub-api.
type releaseChange struct {
	config                  *rest.Config
	namespace, installation string
	image                   string
	compiled                int64
	schema                  releaseSchema
	out                     io.Writer
	// poll and settle bound the wait for both Deployments to roll out;
	// stable is how long they must stay settled and unchanged.
	poll, settle, stable time.Duration
}

func (c releaseChange) deployments(ctx context.Context) (hubAPI, hubWorker apps.Deployment, err error) {
	apiName, workerName := kube.HubDeploymentNames(c.installation)
	if hubAPI, err = kube.ReadHubDeployment(ctx, c.config, c.namespace, apiName); err != nil {
		return
	}
	hubWorker, err = kube.ReadHubDeployment(ctx, c.config, c.namespace, workerName)
	return
}

// run upgrades (an image not in the history: migrate first) or rolls back
// (an image in the history, allowed while the schema floor admits its
// schema), then rolls both Deployments out and settles the record. A failure
// before the record update changes nothing; after it, both images verify
// and a rerun with the same image resumes.
func (c releaseChange) run(ctx context.Context) error {
	if !contracts.ReleaseImageValid(c.image) || c.schema == nil || c.compiled < 1 {
		return cfg.ErrInvalid
	}
	current, err := kube.ReadReleaseRecord(ctx, c.config, c.namespace, c.installation)
	if err != nil {
		return err
	}
	r := current.Record
	hubAPI, hubWorker, err := c.deployments(ctx)
	if err != nil {
		return err
	}
	if !kube.ReleaseDeploymentMatches(hubAPI, r, true) || !kube.ReleaseDeploymentMatches(hubWorker, r, false) {
		return fmt.Errorf("%w: a hub Deployment does not run an image the release record names", cfg.ErrChanged)
	}
	next, rv := r, current.ResourceVersion
	switch {
	case r.Image == c.image && r.Previous == "":
		if !kube.HubDeploymentSettled(hubAPI) || !kube.HubDeploymentSettled(hubWorker) {
			return fmt.Errorf("%w: release revision %d is recorded settled but a hub Deployment is not", cfg.ErrChanged, r.Revision)
		}
		_, err = fmt.Fprintf(c.out, "release already at revision %d (%s)\n", r.Revision, c.image)
		return err
	case r.Image == c.image:
		// Resume the change recorded by an interrupted run.
		fmt.Fprintf(c.out, "resuming release revision %d\n", r.Revision)
	case r.Previous != "":
		return fmt.Errorf("%w: revision %d to %s is not settled; rerun with that image first", ErrReleaseRefused, r.Revision, r.Image)
	default:
		state, e := c.schema.State(ctx)
		if e != nil {
			return e
		}
		var schema int64
		if entry, rollback := r.HistoryEntry(c.image); rollback {
			// Image-only rollback: no migration, and only while the database
			// still serves that release's schema.
			if state.Floor > entry.Schema {
				return fmt.Errorf("%w: the database (floor %d) no longer serves schema %d of %s; restore from backup instead", ErrReleaseRefused, state.Floor, entry.Schema, c.image)
			}
			if entry.Schema != c.compiled || !state.Compatible(c.compiled) {
				return fmt.Errorf("%w: this binary (schema %d) is not the recorded release (schema %d)", ErrReleaseRefused, c.compiled, entry.Schema)
			}
			schema = entry.Schema
		} else {
			planned, e := c.schema.PlannedFloor(state)
			if e != nil {
				return e
			}
			// Phase 2 guard: every retained release must stay runnable.
			if oldest := r.History[0]; planned > oldest.Schema {
				return fmt.Errorf("%w: the migrations raise the floor to %d, past the oldest retained release's schema %d", ErrReleaseRefused, planned, oldest.Schema)
			}
			from, to, e := c.schema.Run(ctx)
			if e != nil {
				return e
			}
			fmt.Fprintf(c.out, "schema %d to %d\n", from, to)
			if state, e = c.schema.State(ctx); e != nil {
				return e
			}
			if !state.Compatible(c.compiled) {
				return fmt.Errorf("%w: the database (head %d, floor %d) does not serve this binary's schema %d", ErrReleaseRefused, state.Head, state.Floor, c.compiled)
			}
			schema = c.compiled
		}
		var launch contracts.ReleaseWorkloads
		if r.Revision == 1 {
			// Leaving revision 1 records the launch generations, which every
			// install-time generation check holds.
			if !kube.HubDeploymentSettled(hubAPI) || !kube.HubDeploymentSettled(hubWorker) {
				return fmt.Errorf("%w: a hub Deployment is not settled at revision 1", cfg.ErrChanged)
			}
			launch = contracts.ReleaseWorkloads{HubAPI: contracts.ReleaseWorkload{Launch: hubAPI.Generation}, HubWorker: contracts.ReleaseWorkload{Launch: hubWorker.Generation}}
		}
		if next, e = r.Next(c.image, schema, launch); e != nil {
			return e
		}
		if rv, e = kube.UpdateReleaseRecord(ctx, c.config, c.namespace, next, rv); e != nil {
			return e
		}
		fmt.Fprintf(c.out, "release revision %d: %s\n", next.Revision, c.image)
	}
	// hub-worker first, then hub-api; each only from the previous image.
	apiName, workerName := kube.HubDeploymentNames(c.installation)
	for _, w := range []struct {
		name string
		gen  int64
	}{{workerName, next.Workloads.HubWorker.Generation}, {apiName, next.Workloads.HubAPI.Generation}} {
		d, e := kube.ReadHubDeployment(ctx, c.config, c.namespace, w.name)
		if e != nil {
			return e
		}
		if d.Spec.Template.Spec.Containers[0].Image == c.image {
			if d.Generation != w.gen {
				return fmt.Errorf("%w: %s runs the target image at an unrecorded generation", cfg.ErrChanged, w.name)
			}
			continue
		}
		if d.Spec.Template.Spec.Containers[0].Image != next.Previous || d.Generation != w.gen-1 {
			return fmt.Errorf("%w: %s does not run the previous release image", cfg.ErrChanged, w.name)
		}
		gen, e := kube.UpdateHubDeploymentImage(ctx, c.config, d, c.image)
		if e != nil {
			return e
		}
		if gen != w.gen {
			return fmt.Errorf("%w: %s reached generation %d, not %d", cfg.ErrChanged, w.name, gen, w.gen)
		}
	}
	// Settled means observed, updated and available, and unchanged (same
	// resourceVersions, so no Ready drop from a crashing process) for stable.
	deadline := time.Now().Add(c.settle)
	var since time.Time
	var seen [2]string
	for {
		hubAPI, hubWorker, err = c.deployments(ctx)
		now := time.Now()
		if err == nil && hubAPI.Spec.Template.Spec.Containers[0].Image == c.image && hubWorker.Spec.Template.Spec.Containers[0].Image == c.image && kube.HubDeploymentSettled(hubAPI) && kube.HubDeploymentSettled(hubWorker) {
			if current := [2]string{hubAPI.ResourceVersion, hubWorker.ResourceVersion}; since.IsZero() || current != seen {
				since, seen = now, current
			}
			if now.Sub(since) >= c.stable {
				break
			}
		} else {
			since = time.Time{}
		}
		if now.After(deadline) {
			return fmt.Errorf("%w: hub Deployments did not settle on %s within %s; rerun to resume", cfg.ErrUnavailable, c.image, c.settle)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.poll):
		}
	}
	settled, err := next.Settled()
	if err != nil {
		return err
	}
	if _, err = kube.UpdateReleaseRecord(ctx, c.config, c.namespace, settled, rv); err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.out, "release revision %d settled on %s\n", settled.Revision, c.image)
	return err
}
