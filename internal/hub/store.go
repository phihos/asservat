package hub

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"asservat.local/asservat/internal/api"
)

//go:embed schema.sql
var schema string

// Store is the hub's PostgreSQL state.
type Store struct {
	db *pgxpool.Pool
	// audit is where every entry of the audit log is also written, as a
	// line of JSON; nil for nowhere (AuditTo).
	audit   io.Writer
	auditMu sync.Mutex
	// audited is called after every entry of the audit log, if set.
	audited func()
}

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

// AuditTo has every entry of the audit log written to w as well, one line
// of JSON each: for an installation whose logs go to a SIEM, which so gets
// the audit log without credentials of the hub. Call it before the store
// is used.
func (s *Store) AuditTo(w io.Writer) { s.audit = w }

func (s *Store) Audit(ctx context.Context, actor, action, capture string, detail any) error {
	b, _ := json.Marshal(detail)
	e := AuditEntry{Actor: actor, Action: action, Detail: b}
	if capture != "" {
		e.Capture = &capture
	}
	// With the capture's number, as the log shows the entry while the capture exists.
	err := s.db.QueryRow(ctx, `WITH a AS (INSERT INTO audit(actor, action, capture_id, detail) VALUES ($1,$2,nullif($3,'')::uuid,$4) RETURNING id, at, capture_id)
 SELECT a.id, a.at, c.number FROM a LEFT JOIN captures c ON c.id = a.capture_id`, actor, action, capture, b).Scan(&e.ID, &e.At, &e.Number)
	if err == nil && s.audited != nil {
		s.audited()
	}
	if err != nil || s.audit == nil {
		return err
	}
	// The entry as the API returns it, marked as what it is among the other lines of a log.
	line, _ := json.Marshal(struct {
		Log string `json:"log"`
		AuditEntry
	}{"audit", e})
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	// The entry is in the database: a line that cannot be written does not
	// undo what was done, and is said where the other output goes.
	if _, err := s.audit.Write(append(line, '\n')); err != nil {
		slog.Error("audit line not written", "id", e.ID, "error", err)
	}
	return nil
}

type AuditEntry struct {
	// ID tells entries of one moment apart: with At it is where a page ends.
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Capture *string   `json:"capture,omitempty"`
	// Number is the capture's, while the capture exists.
	Number *int64          `json:"number,omitempty"`
	Detail json.RawMessage `json:"detail,omitempty"`
}

// AuditLog returns up to limit entries older than before, newest first.
// Of the entries of the moment before itself it returns those with an ID
// below beforeID, so that a page begins where the last one ended.
func (s *Store) AuditLog(ctx context.Context, before time.Time, beforeID int64, limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(ctx, `SELECT a.id, a.at, a.actor, a.action, a.capture_id::text, c.number, a.detail FROM audit a LEFT JOIN captures c ON c.id = a.capture_id
 WHERE (a.at, a.id) < ($1, $2) ORDER BY a.at DESC, a.id DESC LIMIT $3`, before, beforeID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEntry, error) {
		var e AuditEntry
		return e, r.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Capture, &e.Number, &e.Detail)
	})
}

// KeepWatches deletes the watches of clusters that are no longer configured.
func (s *Store) KeepWatches(ctx context.Context, clusters []string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM watches WHERE NOT cluster = ANY($1)`, clusters)
	return err
}

func (s *Store) CreateCapture(ctx context.Context, c api.Capture) error {
	spec, _ := json.Marshal(c.CaptureRequest)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO captures(id, requester, cluster, request, sensitive, state, approver, expires_at, approvals) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		c.ID, c.Requester, c.Cluster, spec, c.Sensitive, c.State, c.Approver, c.ExpiresAt, names(c.Approvals)); err != nil {
		return err
	}
	for _, t := range c.Tasks {
		if _, err := tx.Exec(ctx, `INSERT INTO tasks(capture_id, pod, node, state) VALUES ($1,$2,$3,$4)`, c.ID, t.Pod, t.Node, t.State); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

const captureColumns = `c.id::text, c.number, c.requester, c.request, c.sensitive, c.state, c.message, c.approver, c.created_at, c.finished_at, c.expires_at, c.stopped_at, c.shared, c.approvals,
 coalesce((SELECT json_agg(json_build_object('pod', pod, 'node', node, 'state', state, 'message', message, 'recordings', recordings) ORDER BY pod) FROM tasks WHERE capture_id = c.id), '[]'),
 coalesce((SELECT json_agg(json_build_object('name', name, 'size', size, 'sha256', sha256, 'stored', CASE WHEN packed THEN stored ELSE 0 END) ORDER BY name) FROM artifacts WHERE capture_id = c.id), '[]')`

func scanCapture(r pgx.CollectableRow) (api.Capture, error) {
	var c api.Capture
	var request, tasks, artifacts []byte
	if err := r.Scan(&c.ID, &c.Number, &c.Requester, &request, &c.Sensitive, &c.State, &c.Message, &c.Approver, &c.CreatedAt, &c.FinishedAt, &c.ExpiresAt, &c.StoppedAt, &c.Shared, &c.Approvals, &tasks, &artifacts); err != nil {
		return c, err
	}
	if err := json.Unmarshal(request, &c.CaptureRequest); err != nil {
		return c, err
	}
	c.Normalize() // rows from before a request could hold several recordings
	if err := json.Unmarshal(tasks, &c.Tasks); err != nil {
		return c, err
	}
	if err := json.Unmarshal(artifacts, &c.Artifacts); err != nil {
		return c, err
	}
	for i, a := range c.Artifacts {
		c.Artifacts[i].Viewer, c.Artifacts[i].Recording = api.ViewerOf(a.Name), api.RecordingOf(a.Name)
	}
	return c, nil
}

// TaskOf returns what an agent's report or upload for a pod of a capture
// needs of the capture: its request and state, and whether the pod is one
// of its tasks. It reads no other task and no file's record: a capture has
// a task and files for every pod, each pod reports several times, and
// reading all of them for each report took time and memory by the square
// of the pods (measured with 2,000: 39 seconds of the hub's processor and
// 2 GiB for one capture).
func (s *Store) TaskOf(ctx context.Context, id, pod string) (reported, error) {
	c := reported{}
	var request []byte
	err := s.db.QueryRow(ctx, `SELECT c.id::text, c.request, c.state, EXISTS (SELECT 1 FROM tasks WHERE capture_id = c.id AND pod = $2)
 FROM captures c WHERE c.id = $1::uuid`, id, pod).Scan(&c.ID, &request, &c.State, &c.Task)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(request, &c.Request); err != nil {
		return c, err
	}
	c.Request.Normalize()
	return c, nil
}

// reported is what the hub reads of a capture when an agent reports on a
// pod of it or sends a file: no more than these.
type reported struct {
	ID      string
	Request api.CaptureRequest
	State   string
	// Task tells whether the pod is one of the capture's.
	Task bool
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
func (s *Store) Captures(ctx context.Context, requester string, shared []Place, before time.Time, limit int) ([]api.Capture, error) {
	clusters, namespaces := make([]string, len(shared)), make([]string, len(shared))
	for i, p := range shared {
		clusters[i], namespaces[i] = p.Cluster, p.Namespace
	}
	rows, err := s.db.Query(ctx, `SELECT `+captureColumns+` FROM captures c WHERE ($1 = '' OR c.requester = $1
  OR c.shared AND (c.cluster, c.request->>'namespace') IN (SELECT * FROM unnest($4::text[], $5::text[])))
 AND c.created_at < $2 ORDER BY c.created_at DESC LIMIT $3`, requester, before, limit, clusters, namespaces)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCapture)
}

// Counts is how much the hub holds, for its metrics.
type Counts struct {
	States []struct {
		State string
		Count int64
	}
	Watches, Files, Bytes int64
}

// Counts counts captures by state, watches and stored files.
func (s *Store) Counts(ctx context.Context) (Counts, error) {
	var c Counts
	rows, err := s.db.Query(ctx, `SELECT state, count(*) FROM captures GROUP BY state ORDER BY state`)
	if err != nil {
		return c, err
	}
	if c.States, err = pgx.CollectRows(rows, pgx.RowToStructByPos[struct {
		State string
		Count int64
	}]); err != nil {
		return c, err
	}
	err = s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM watches), (SELECT count(*) FROM artifacts), (SELECT coalesce(sum(coalesce(stored, size)), 0) FROM artifacts)`).Scan(&c.Watches, &c.Files, &c.Bytes)
	return c, err
}

// Place is a namespace of a cluster.
type Place struct{ Cluster, Namespace string }

// SharedPlaces lists the namespaces that hold shared captures of others
// than the requester.
func (s *Store) SharedPlaces(ctx context.Context, requester string) ([]Place, error) {
	rows, err := s.db.Query(ctx, `SELECT DISTINCT cluster, request->>'namespace' FROM captures WHERE shared AND requester <> $1`, requester)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Place])
}

// Share says whether a capture is shared.
func (s *Store) Share(ctx context.Context, id string, shared bool) error {
	_, err := s.db.Exec(ctx, `UPDATE captures SET shared = $2 WHERE id = $1::uuid`, id, shared)
	return err
}

// names is a list of names as the database takes it: never NULL.
func names(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// approved is what an approval makes of the columns of a request that
// needs so many: the approver's name joins those who approved, and with
// the last of them approver names them all.
const approved = `approvals = approvals || ARRAY[$2::text],
 approver = CASE WHEN cardinality(approvals) + 1 >= $3 THEN array_to_string(approvals || ARRAY[$2::text], ', ') ELSE '' END`

// Decide records one person's word on a capture that awaits approval: a
// refusal denies it, an approval starts it once it has as many as needed.
// It reports false when the capture was already decided, or approved by
// this person.
func (s *Store) Decide(ctx context.Context, id, approver, state string, needed int) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var tag pgconn.CommandTag
	if state == api.StateDenied {
		tag, err = tx.Exec(ctx, `UPDATE captures SET state = 'Denied', approver = $2, finished_at = now() WHERE id = $1::uuid AND state = 'PendingApproval'`, id, approver)
	} else {
		tag, err = tx.Exec(ctx, `UPDATE captures SET `+approved+`,
 state = CASE WHEN cardinality(approvals) + 1 >= $3 THEN $4 ELSE state END
 WHERE id = $1::uuid AND state = 'PendingApproval' AND NOT ($2 = ANY(approvals))`, id, approver, needed, state)
	}
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

// Stop marks a running capture as stopped, so that tasks which reach their
// agent later know it too. It reports false if the capture does not run.
func (s *Store) Stop(ctx context.Context, id string) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE captures SET stopped_at = coalesce(stopped_at, now()) WHERE id = $1::uuid AND state = 'Running'`, id)
	return tag.RowsAffected() == 1, err
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
	var stored []byte
	err = tx.QueryRow(ctx, `UPDATE tasks SET state = $3, message = $4 WHERE capture_id = $1::uuid AND pod = $2 AND state IN ('Queued','Running') RETURNING recordings`, id, st.Pod, st.State, st.Message).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if st.Recordings != nil {
		// A recording keeps the time at which the hub first saw it run.
		var before []api.RecordingStatus
		if err := json.Unmarshal(stored, &before); err != nil {
			return err
		}
		now := time.Now()
		for i, rec := range st.Recordings {
			st.Recordings[i].StartedAt = nil
			for _, b := range before {
				if b.Kind == rec.Kind {
					st.Recordings[i].StartedAt = b.StartedAt
				}
			}
			if st.Recordings[i].StartedAt == nil && rec.State != api.StateWaiting {
				st.Recordings[i].StartedAt = &now
			}
		}
		progress, _ := json.Marshal(st.Recordings)
		if _, err := tx.Exec(ctx, `UPDATE tasks SET recordings = $3 WHERE capture_id = $1::uuid AND pod = $2`, id, st.Pod, progress); err != nil {
			return err
		}
	}
	// While a task of the capture is open, the capture runs, and that is
	// told without counting its tasks: a capture has two reports for every
	// pod, and counting all pods at each took PostgreSQL time by their
	// square. The tasks are counted once, when the last one has ended.
	var open bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tasks WHERE capture_id = $1::uuid AND state IN ('Queued','Running'))`, id).Scan(&open); err != nil {
		return err
	}
	if open {
		if _, err := tx.Exec(ctx, `UPDATE captures SET state = 'Running', message = '' WHERE id = $1::uuid AND (state = 'Queued' OR state = 'Running' AND message <> '')`, id); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `UPDATE captures c SET
  state = CASE WHEN t.open > 0 THEN 'Running' WHEN t.completed > 0 THEN 'Completed' ELSE 'Failed' END,
  message = CASE WHEN t.open > 0 THEN '' ELSE concat_ws('; ',
    CASE WHEN t.failed > 0 THEN t.failed || ' of ' || t.total || ' pods failed' END,
    CASE WHEN r.failed > 0 THEN r.failed || ' of ' || r.total || ' recordings failed' END) END,
  finished_at = CASE WHEN t.open = 0 THEN now() END
 FROM (SELECT count(*) FILTER (WHERE state IN ('Queued','Running')) AS open, count(*) FILTER (WHERE state = 'Completed') AS completed,
   count(*) FILTER (WHERE state = 'Failed') AS failed, count(*) AS total FROM tasks WHERE capture_id = $1::uuid) t,
  -- The recordings of the pods that delivered: one of them can have failed while the others gave files.
  (SELECT count(*) FILTER (WHERE rec->>'state' = 'Failed') AS failed, count(*) AS total
   FROM tasks, jsonb_array_elements(recordings) rec WHERE capture_id = $1::uuid AND tasks.state = 'Completed') r
 WHERE c.id = $1::uuid AND c.state IN ('Queued','Running')`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// OpenTasks returns a node's tasks that are approved and have not finished,
// for delivery when its agent connects. A task that had already started is
// marked so: its agent either still runs it or lost it in a restart.
func (s *Store) OpenTasks(ctx context.Context, cluster, node string) ([]api.Command, error) {
	rows, err := s.db.Query(ctx, `SELECT c.id::text, t.pod, t.state = 'Running', c.stopped_at IS NOT NULL, c.request FROM tasks t JOIN captures c ON c.id = t.capture_id
 WHERE c.cluster = $1 AND t.node = $2 AND t.state IN ('Queued','Running') AND c.state IN ('Queued','Running')`, cluster, node)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (api.Command, error) {
		cmd := api.Command{Type: "task", Task: &api.TaskAssignment{}}
		var request []byte
		if err := r.Scan(&cmd.ID, &cmd.Task.Pod, &cmd.Task.Started, &cmd.Task.Stopped, &request); err != nil {
			return cmd, err
		}
		if err := json.Unmarshal(request, &cmd.Task.Request); err != nil {
			return cmd, err
		}
		cmd.Task.Request.Normalize()
		return cmd, nil
	})
}

type storedArtifact struct {
	api.Artifact
	Blob string
	Key  []byte
	// Packed tells that the blob holds the file without its holes (see
	// the package holes): it is unpacked for whoever reads it.
	Packed bool
}

// stored is what the file takes of the store, before encryption: what a
// packed file was sent as, and of the others their size.
func (a storedArtifact) stored() int64 {
	if a.Packed {
		return a.Stored
	}
	return a.Size
}

// AddArtifact records a stored file of a capture that is still open. It
// reports false when the capture has ended or is gone.
func (s *Store) AddArtifact(ctx context.Context, capture string, a storedArtifact) (bool, error) {
	tag, err := s.db.Exec(ctx, `INSERT INTO artifacts(capture_id, name, size, sha256, blob, wrapped_key, packed, stored)
 SELECT id, $2, $3, $4, $5, $6, $7, $8 FROM captures WHERE id = $1::uuid AND state IN ('Queued','Running') FOR SHARE`, capture, a.Name, a.Size, a.SHA256, a.Blob, a.Key, a.Packed, a.stored())
	return tag.RowsAffected() == 1, err
}

// ReplaceArtifact records a stored file of a capture in place of the one
// of its name, if there is one, whose blob it returns to delete. It
// reports false when the capture is gone.
func (s *Store) ReplaceArtifact(ctx context.Context, capture string, a storedArtifact) (old string, replaced bool, err error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback(ctx)
	// The row lock keeps the capture from being deleted meanwhile.
	if tag, err := tx.Exec(ctx, `SELECT 1 FROM captures WHERE id = $1::uuid FOR SHARE`, capture); err != nil || tag.RowsAffected() == 0 {
		return "", false, err
	}
	if err := tx.QueryRow(ctx, `DELETE FROM artifacts WHERE capture_id = $1::uuid AND name = $2 RETURNING blob`, capture, a.Name).Scan(&old); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO artifacts(capture_id, name, size, sha256, blob, wrapped_key, packed, stored) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)`, capture, a.Name, a.Size, a.SHA256, a.Blob, a.Key, a.Packed, a.stored()); err != nil {
		return "", false, err
	}
	return old, true, tx.Commit(ctx)
}

func (s *Store) Artifact(ctx context.Context, capture, name string) (storedArtifact, error) {
	a := storedArtifact{}
	err := s.db.QueryRow(ctx, `SELECT name, size, sha256, blob, wrapped_key, packed FROM artifacts WHERE capture_id = $1::uuid AND name = $2`, capture, name).Scan(&a.Name, &a.Size, &a.SHA256, &a.Blob, &a.Key, &a.Packed)
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
	// The row lock waits for uploads that are recording an artifact, so the
	// list below is complete; later ones find no capture and delete their blob.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM captures WHERE id = $1::uuid FOR UPDATE`, id); err != nil {
		return nil, err
	}
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

func (s *Store) CreateWatch(ctx context.Context, w api.Watch, groups []string) error {
	request, _ := json.Marshal(w.CaptureRequest)
	g, _ := json.Marshal(groups)
	condition, _ := json.Marshal(w.When)
	_, err := s.db.Exec(ctx, `INSERT INTO watches(id, requester, groups, cluster, request, selector, remaining, sensitive, approver, condition, before_seconds, approvals) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		w.ID, w.Requester, g, w.Cluster, request, w.Selector, w.Remaining, w.Sensitive, w.Approver, condition, w.BeforeSeconds, names(w.Approvals))
	return err
}

const watchColumns = `id::text, requester, groups, request, selector, remaining, created_at, sensitive, approver, condition, before_seconds, approvals`

// scanWatch also returns the groups of the user who created the watch.
func scanWatch(r pgx.Row) (api.Watch, []string, error) {
	var w api.Watch
	var groups []string
	var request, g, condition []byte
	if err := r.Scan(&w.ID, &w.Requester, &g, &request, &w.Selector, &w.Remaining, &w.CreatedAt, &w.Sensitive, &w.Approver, &condition, &w.BeforeSeconds, &w.Approvals); err != nil {
		return w, nil, err
	}
	if err := json.Unmarshal(condition, &w.When); err != nil {
		return w, nil, err
	}
	if err := json.Unmarshal(g, &groups); err != nil {
		return w, nil, err
	}
	if err := json.Unmarshal(request, &w.CaptureRequest); err != nil {
		return w, nil, err
	}
	w.Normalize()
	return w, groups, nil
}

// Watches lists a requester's watches, or everyone's for an empty requester,
// newest first.
func (s *Store) Watches(ctx context.Context, requester string) ([]api.Watch, error) {
	return s.watches(ctx, `($1 = '' OR requester = $1)`, requester)
}

// ActiveWatches lists the watches that a cluster's agents observe: those
// that need no approval or have it.
func (s *Store) ActiveWatches(ctx context.Context, cluster string) ([]api.Watch, error) {
	return s.watches(ctx, `cluster = $1 AND (NOT sensitive OR approver <> '')`, cluster)
}

func (s *Store) watches(ctx context.Context, where, arg string) ([]api.Watch, error) {
	rows, err := s.db.Query(ctx, `SELECT `+watchColumns+` FROM watches WHERE `+where+` AND remaining > 0 ORDER BY created_at DESC`, arg)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (api.Watch, error) {
		w, _, err := scanWatch(r)
		return w, err
	})
}

// Awaiting lists the captures and watches that await approval.
func (s *Store) Awaiting(ctx context.Context) ([]api.Capture, []api.Watch, error) {
	rows, err := s.db.Query(ctx, `SELECT `+captureColumns+` FROM captures c WHERE c.state = 'PendingApproval' ORDER BY c.created_at`)
	if err != nil {
		return nil, nil, err
	}
	captures, err := pgx.CollectRows(rows, scanCapture)
	if err != nil {
		return nil, nil, err
	}
	watches, err := s.watches(ctx, `sensitive AND approver = '' AND $1 = ''`, "")
	return captures, watches, err
}

func (s *Store) Watch(ctx context.Context, id string) (api.Watch, []string, error) {
	w, groups, err := scanWatch(s.db.QueryRow(ctx, `SELECT `+watchColumns+` FROM watches WHERE id = $1::uuid`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return w, nil, ErrNotFound
	}
	return w, groups, err
}

// FireWatch counts one crash against the watch and reports how many remain,
// or ErrNotFound if none did. The caller deletes the watch after its last
// crash is recorded, or gives the crash back with RefundWatch.
func (s *Store) FireWatch(ctx context.Context, id string) (int, error) {
	var remaining int
	err := s.db.QueryRow(ctx, `UPDATE watches SET remaining = remaining - 1 WHERE id = $1::uuid AND remaining > 0 RETURNING remaining`, id).Scan(&remaining)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return remaining, err
}

// FireWatchOnce is FireWatch for an event that can be told several times:
// it counts the event, named by key, only the first time.
func (s *Store) FireWatchOnce(ctx context.Context, id, key string) (int, error) {
	var remaining int
	err := s.db.QueryRow(ctx, `UPDATE watches SET remaining = remaining - 1, fired = fired || to_jsonb($2::text)
 WHERE id = $1::uuid AND remaining > 0 AND NOT fired ? $2 RETURNING remaining`, id, key).Scan(&remaining)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return remaining, err
}

// RefundWatch gives a watch's count back for something that was counted
// and then not recorded, and forgets its key, if it had one, so that it
// can be counted again.
func (s *Store) RefundWatch(ctx context.Context, id, key string) error {
	_, err := s.db.Exec(ctx, `UPDATE watches SET remaining = remaining + 1, fired = fired - $2::text WHERE id = $1::uuid`, id, key)
	return err
}

// ApproveWatch records one person's approval of a sensitive watch that
// awaits it, which is approved once it has as many as needed, and reports
// whether it did: not for a watch that is approved, or by this person.
func (s *Store) ApproveWatch(ctx context.Context, id, approver string, needed int) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE watches SET `+approved+` WHERE id = $1::uuid AND sensitive AND approver = '' AND NOT ($2 = ANY(approvals))`, id, approver, needed)
	return tag.RowsAffected() == 1, err
}

func (s *Store) DeleteWatch(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM watches WHERE id = $1::uuid`, id)
	return err
}
