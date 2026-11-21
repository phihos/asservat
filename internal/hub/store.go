package hub

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"asservat.local/asservat/internal/api"
)

//go:embed schema.sql
var schema string

// Store is the hub's PostgreSQL state.
type Store struct{ db *pgxpool.Pool }

var ErrNotFound = errors.New("not found")

func OpenStore(ctx context.Context, dsn string) (*Store, error) {
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(ctx, schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() { s.db.Close() }

func (s *Store) Audit(ctx context.Context, actor, action, capture string, detail any) error {
	b, _ := json.Marshal(detail)
	_, err := s.db.Exec(ctx, `INSERT INTO audit(actor, action, capture_id, detail) VALUES ($1,$2,nullif($3,'')::uuid,$4)`, actor, action, capture, b)
	return err
}

type AuditEntry struct {
	At      time.Time       `json:"at"`
	Actor   string          `json:"actor"`
	Action  string          `json:"action"`
	Capture *string         `json:"capture,omitempty"`
	Detail  json.RawMessage `json:"detail,omitempty"`
}

// AuditLog returns up to limit entries older than before, newest first.
func (s *Store) AuditLog(ctx context.Context, before time.Time, limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(ctx, `SELECT at, actor, action, capture_id::text, detail FROM audit WHERE at < $1 ORDER BY at DESC, id DESC LIMIT $2`, before, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEntry, error) {
		var e AuditEntry
		return e, r.Scan(&e.At, &e.Actor, &e.Action, &e.Capture, &e.Detail)
	})
}

func (s *Store) AddCluster(ctx context.Context, name string, tokenHash []byte) error {
	_, err := s.db.Exec(ctx, `INSERT INTO clusters(name, token_sha256) VALUES ($1,$2) ON CONFLICT (name) DO UPDATE SET token_sha256 = excluded.token_sha256`, name, tokenHash)
	return err
}

func (s *Store) DeleteCluster(ctx context.Context, name string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM clusters WHERE name = $1`, name)
	return err
}

func (s *Store) Clusters(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT name FROM clusters ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// ClusterByToken returns the cluster whose join token has this hash.
func (s *Store) ClusterByToken(ctx context.Context, tokenHash []byte) (string, error) {
	var name string
	err := s.db.QueryRow(ctx, `SELECT name FROM clusters WHERE token_sha256 = $1`, tokenHash).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}

func (s *Store) CreateCapture(ctx context.Context, c api.Capture) error {
	spec, _ := json.Marshal(c.CaptureRequest)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO captures(id, requester, cluster, request, sensitive, state, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		c.ID, c.Requester, c.Cluster, spec, c.Sensitive, c.State, c.ExpiresAt); err != nil {
		return err
	}
	for _, t := range c.Tasks {
		if _, err := tx.Exec(ctx, `INSERT INTO tasks(capture_id, pod, node, state) VALUES ($1,$2,$3,$4)`, c.ID, t.Pod, t.Node, t.State); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

const captureColumns = `c.id::text, c.requester, c.request, c.sensitive, c.state, c.message, c.approver, c.created_at, c.finished_at, c.expires_at,
 coalesce((SELECT json_agg(json_build_object('pod', pod, 'node', node, 'state', state, 'message', message) ORDER BY pod) FROM tasks WHERE capture_id = c.id), '[]'),
 coalesce((SELECT json_agg(json_build_object('name', name, 'size', size, 'sha256', sha256) ORDER BY name) FROM artifacts WHERE capture_id = c.id), '[]')`

func scanCapture(r pgx.CollectableRow) (api.Capture, error) {
	var c api.Capture
	var request, tasks, artifacts []byte
	if err := r.Scan(&c.ID, &c.Requester, &request, &c.Sensitive, &c.State, &c.Message, &c.Approver, &c.CreatedAt, &c.FinishedAt, &c.ExpiresAt, &tasks, &artifacts); err != nil {
		return c, err
	}
	if err := json.Unmarshal(request, &c.CaptureRequest); err != nil {
		return c, err
	}
	if err := json.Unmarshal(tasks, &c.Tasks); err != nil {
		return c, err
	}
	return c, json.Unmarshal(artifacts, &c.Artifacts)
}

func (s *Store) Capture(ctx context.Context, id string) (api.Capture, error) {
	rows, err := s.db.Query(ctx, `SELECT `+captureColumns+` FROM captures c WHERE c.id = $1::uuid`, id)
	if err != nil {
		return api.Capture{}, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, scanCapture)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

// Captures lists captures created before the given time, newest first. An
// empty requester lists everyone's.
func (s *Store) Captures(ctx context.Context, requester string, before time.Time, limit int) ([]api.Capture, error) {
	rows, err := s.db.Query(ctx, `SELECT `+captureColumns+` FROM captures c WHERE ($1 = '' OR c.requester = $1) AND c.created_at < $2 ORDER BY c.created_at DESC LIMIT $3`, requester, before, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCapture)
}

// Decide moves a capture out of PendingApproval. It reports false when the
// capture was already decided.
func (s *Store) Decide(ctx context.Context, id, approver, state string) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE captures SET state = $3, approver = $2, finished_at = CASE WHEN $3 = 'Denied' THEN now() END WHERE id = $1::uuid AND state = 'PendingApproval'`, id, approver, state)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	if state == api.StateDenied {
		if _, err := tx.Exec(ctx, `UPDATE tasks SET state = 'Cancelled' WHERE capture_id = $1::uuid`, id); err != nil {
			return false, err
		}
	}
	return true, tx.Commit(ctx)
}

// Cancel ends a capture that has not finished and returns whether it did.
func (s *Store) Cancel(ctx context.Context, id string) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE captures SET state = 'Cancelled', finished_at = now() WHERE id = $1::uuid AND state IN ('PendingApproval','Queued','Running')`, id)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE tasks SET state = 'Cancelled' WHERE capture_id = $1::uuid AND state IN ('Queued','Running')`, id); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// SetTask records an agent's report and derives the capture's state from its
// tasks: Running while any task runs, then Completed if at least one task
// completed, otherwise Failed.
func (s *Store) SetTask(ctx context.Context, id string, st api.TaskStatus) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Reports of several pods serialize on the capture row, so each one sees
	// the others' task states when it derives the capture's state.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM captures WHERE id = $1::uuid FOR UPDATE`, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE tasks SET state = $3, message = $4 WHERE capture_id = $1::uuid AND pod = $2 AND state IN ('Queued','Running')`, id, st.Pod, st.State, st.Message)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE captures c SET
  state = CASE WHEN t.open > 0 THEN 'Running' WHEN t.completed > 0 THEN 'Completed' ELSE 'Failed' END,
  message = CASE WHEN t.open = 0 AND t.failed > 0 THEN t.failed || ' of ' || t.total || ' pods failed' ELSE '' END,
  finished_at = CASE WHEN t.open = 0 THEN now() END
 FROM (SELECT count(*) FILTER (WHERE state IN ('Queued','Running')) AS open, count(*) FILTER (WHERE state = 'Completed') AS completed,
   count(*) FILTER (WHERE state = 'Failed') AS failed, count(*) AS total FROM tasks WHERE capture_id = $1::uuid) t
 WHERE c.id = $1::uuid AND c.state IN ('Queued','Running')`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// OpenTasks returns a node's tasks that are approved and have not finished,
// for delivery when its agent connects. A task that had already started is
// marked so: its agent either still runs it or lost it in a restart.
func (s *Store) OpenTasks(ctx context.Context, cluster, node string) ([]api.Command, error) {
	rows, err := s.db.Query(ctx, `SELECT c.id::text, t.pod, t.state = 'Running', c.request FROM tasks t JOIN captures c ON c.id = t.capture_id
 WHERE c.cluster = $1 AND t.node = $2 AND t.state IN ('Queued','Running') AND c.state IN ('Queued','Running')`, cluster, node)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (api.Command, error) {
		cmd := api.Command{Type: "task", Task: &api.TaskAssignment{}}
		var request []byte
		if err := r.Scan(&cmd.ID, &cmd.Task.Pod, &cmd.Task.Started, &request); err != nil {
			return cmd, err
		}
		return cmd, json.Unmarshal(request, &cmd.Task.Request)
	})
}

type storedArtifact struct {
	api.Artifact
	Blob string
	Key  []byte
}

func (s *Store) AddArtifact(ctx context.Context, capture string, a storedArtifact) error {
	_, err := s.db.Exec(ctx, `INSERT INTO artifacts(capture_id, name, size, sha256, blob, wrapped_key) VALUES ($1::uuid,$2,$3,$4,$5,$6)`, capture, a.Name, a.Size, a.SHA256, a.Blob, a.Key)
	return err
}

func (s *Store) Artifact(ctx context.Context, capture, name string) (storedArtifact, error) {
	a := storedArtifact{}
	err := s.db.QueryRow(ctx, `SELECT name, size, sha256, blob, wrapped_key FROM artifacts WHERE capture_id = $1::uuid AND name = $2`, capture, name).Scan(&a.Name, &a.Size, &a.SHA256, &a.Blob, &a.Key)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// DeleteCapture removes a capture and returns the blobs to delete.
func (s *Store) DeleteCapture(ctx context.Context, id string) ([]string, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT blob FROM artifacts WHERE capture_id = $1::uuid`, id)
	if err != nil {
		return nil, err
	}
	blobs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM captures WHERE id = $1::uuid`, id); err != nil {
		return nil, err
	}
	return blobs, tx.Commit(ctx)
}

// Expired returns the captures whose retention has ended and the next expiry
// after now, if any.
func (s *Store) Expired(ctx context.Context) (ids []string, next *time.Time, err error) {
	rows, err := s.db.Query(ctx, `SELECT id::text FROM captures WHERE expires_at <= now()`)
	if err != nil {
		return nil, nil, err
	}
	if ids, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return nil, nil, err
	}
	err = s.db.QueryRow(ctx, `SELECT min(expires_at) FROM captures WHERE expires_at > now()`).Scan(&next)
	return ids, next, err
}
