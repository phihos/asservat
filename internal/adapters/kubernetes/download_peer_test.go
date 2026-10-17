package kubernetes

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type peerTokenFunc func(context.Context) ([]byte, error)

func (f peerTokenFunc) ReadDownloadPeerToken(c context.Context) ([]byte, error) { return f(c) }
func TestDownloadPeerAttestationChecks(t *testing.T) {
	for _, mode := range []string{"valid", "short-token", "denied-review", "wrong-audience", "no-audience", "unbound-token", "wrong-user", "wrong-account", "pod-replaced", "account-replaced", "job-replaced", "namespace-replaced", "changed-pod-spec", "changed-job-spec", "wrong-owner", "completed-job", "failed-job", "suspended-job", "failed-pod", "deleting-pod", "deleting-account", "deleting-job", "revoked-during-read", "changed-during-read", "expired-read", "expired-token", "unbounded-token", "opaque-token", "duplicate-exp", "error-redaction", "cancelled", "wrong-session", "wrong-peer"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
			b := value.KeyWorkerBinding{InstallationID: "00000000-0000-4000-8000-000000000001", DownloadID: "00000000-0000-4000-8000-000000000002", ClusterID: permissionCluster, Namespace: permissionControl.Name, NamespaceUID: permissionControl.UID, ServiceAccount: "acquisition", ServiceAccountUID: "account-uid", Job: "download", JobUID: "job-uid", Pod: "download-worker", PodUID: "00000000-0000-4000-8000-000000000003"}
			podSpec := map[string]any{"serviceAccountName": b.ServiceAccount, "containers": []any{map[string]any{"name": "worker", "image": "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64)}}}
			jobSpec := map[string]any{"template": map[string]any{"spec": podSpec}}
			pJSON, _ := json.Marshal(podSpec)
			jJSON, _ := json.Marshal(jobSpec)
			b.PodSpec, _ = WorkerSpecDigest("Pod", pJSON)
			b.JobSpec, _ = WorkerSpecDigest("Job", jJSON)
			peer := value.KeyPeer{InstallationID: b.InstallationID, PeerID: b.PodUID, Role: "acquisition", Certificate: artifact.Digest{1}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
			expiry := now.Add(time.Minute).Unix()
			iat := now.Add(-time.Second).Unix()
			switch mode {
			case "expired-token":
				expiry = now.Unix()
			case "unbounded-token":
				expiry = now.Add(2 * time.Hour).Unix()
			case "short-token":
				expiry = now.Add(time.Second).Unix()
			}
			payload, _ := json.Marshal(map[string]int64{"exp": expiry, "iat": iat})
			if mode == "duplicate-exp" {
				payload = []byte(`{"exp":1791633660,"exp":1791633661,"iat":1791633599}`)
			}
			token := []byte("e30." + base64.RawURLEncoding.EncodeToString(payload) + ".synthetic-signature")
			if mode == "opaque-token" {
				token = []byte("synthetic-opaque")
			}
			reviews, pods := 0, 0
			var clock *atomic.Int64
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews" {
					reviews++
					var req struct {
						Spec struct {
							Token     string
							Audiences []string
						}
					}
					if json.NewDecoder(r.Body).Decode(&req) != nil || req.Spec.Token != string(token) || len(req.Spec.Audiences) != 1 || req.Spec.Audiences[0] != DownloadPeerAudience(b.InstallationID) {
						t.Error("invalid private TokenReview request")
					}
					if mode == "error-redaction" {
						w.WriteHeader(500)
						_, _ = w.Write(token)
						return true
					}
					aud := []string{DownloadPeerAudience(b.InstallationID)}
					if mode == "wrong-audience" {
						aud = []string{"other"}
					}
					if mode == "no-audience" {
						aud = nil
					}
					extra := map[string][]string{"authentication.kubernetes.io/pod-name": {b.Pod}, "authentication.kubernetes.io/pod-uid": {b.PodUID}}
					if mode == "unbound-token" {
						extra = nil
					}
					uid := b.ServiceAccountUID
					user := "system:serviceaccount:" + b.Namespace + ":" + b.ServiceAccount
					if mode == "wrong-account" {
						uid = "other"
					}
					if mode == "wrong-user" {
						user = "system:serviceaccount:other:acquisition"
					}
					permissionReply(w, map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "status": map[string]any{"authenticated": mode != "denied-review" && !(mode == "revoked-during-read" && reviews > 1), "audiences": aud, "user": map[string]any{"username": user, "uid": uid, "extra": extra}}})
					return true
				}
				if r.URL.Path == "/api/v1/namespaces/"+b.Namespace && mode == "namespace-replaced" {
					permissionReply(w, permissionNamespace(b.Namespace, "different"))
					return true
				}
				kind, name, uid, version := "", "", "", "v1"
				switch r.URL.Path {
				case "/api/v1/namespaces/" + b.Namespace + "/serviceaccounts/" + b.ServiceAccount:
					kind, name, uid = "ServiceAccount", b.ServiceAccount, b.ServiceAccountUID
				case "/apis/batch/v1/namespaces/" + b.Namespace + "/jobs/" + b.Job:
					kind, name, uid, version = "Job", b.Job, b.JobUID, "batch/v1"
				case "/api/v1/namespaces/" + b.Namespace + "/pods/" + b.Pod:
					kind, name, uid = "Pod", b.Pod, b.PodUID
					pods++
				default:
					return false
				}
				if (kind == "Pod" && mode == "pod-replaced") || (kind == "Job" && mode == "job-replaced") || (kind == "ServiceAccount" && mode == "account-replaced") {
					uid = "different"
				}
				m := map[string]any{"name": name, "namespace": b.Namespace, "uid": uid, "resourceVersion": "rv"}
				if (kind == "Pod" && mode == "deleting-pod") || (kind == "Job" && mode == "deleting-job") || (kind == "ServiceAccount" && mode == "deleting-account") {
					m["deletionTimestamp"] = "2026-10-10T12:00:00Z"
				}
				object := map[string]any{"apiVersion": version, "kind": kind, "metadata": m, "status": map[string]any{}}
				if kind == "Job" {
					object["spec"] = jobSpec
					if mode == "changed-job-spec" {
						object["spec"] = map[string]any{"parallelism": 99}
					}
					if mode == "completed-job" {
						object["status"] = map[string]any{"completionTime": "2026-10-10T12:00:00Z"}
					}
					if mode == "failed-job" {
						object["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Failed", "status": "True"}}}
					}
					if mode == "suspended-job" {
						object["spec"] = map[string]any{"suspend": true}
					}
				}
				if kind == "Pod" {
					owner := b.JobUID
					if mode == "wrong-owner" {
						owner = "other"
					}
					m["ownerReferences"] = []any{map[string]any{"apiVersion": "batch/v1", "kind": "Job", "name": b.Job, "uid": owner, "controller": true}}
					object["spec"] = podSpec
					object["status"] = map[string]any{"phase": "Running"}
					if mode == "failed-pod" {
						object["status"] = map[string]any{"phase": "Failed"}
					}
					if mode == "changed-pod-spec" || (mode == "changed-during-read" && pods > 1) {
						object["spec"] = map[string]any{"serviceAccountName": "other"}
					}
					if mode == "expired-read" {
						clock.Add(int64(5 * time.Second))
					}
				}
				permissionReply(w, object)
				return true
			})
			clock = f.clock
			source, e := NewDownloadPeerAttester(f.client, b, peerTokenFunc(func(context.Context) ([]byte, error) { return bytes.Clone(token), nil }))
			if e != nil {
				t.Fatal(e)
			}
			session := b.DownloadID
			if mode == "wrong-session" {
				session = "00000000-0000-4000-8000-000000000099"
			}
			if mode == "wrong-peer" {
				peer.PeerID = session
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			proof, e := source.ReadDownloadPeerProof(ctx, session, peer)
			if mode == "valid" || mode == "short-token" {
				until := now.Add(5 * time.Second)
				if mode == "short-token" {
					until = now.Add(time.Second)
				}
				if e != nil || !proof.Valid(now) || proof.Binding != b || !proof.FreshUntil.Equal(until) || reviews != 2 {
					t.Fatal("valid worker rejected", e, reviews)
				}
				out, _ := json.Marshal(proof)
				if bytes.Contains(out, token) || bytes.Contains(out, []byte("synthetic.invalid")) {
					t.Fatal("token/spec leaked into proof")
				}
			} else if e == nil {
				t.Fatal("unsafe worker accepted")
			} else if strings.Contains(e.Error(), string(token)) {
				t.Fatal("API error leaked token")
			}
		})
	}
}
