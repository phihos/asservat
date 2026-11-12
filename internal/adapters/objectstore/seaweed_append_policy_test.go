package objectstore

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestSeaweedAppendBucketPolicyPreservesSIDsAndExactReplay(t *testing.T) {
	for _, mode := range []string{"append", "conflict", "pending", "foreign-tags", "suspended", "unknown-put"} {
		t.Run(mode, func(t *testing.T) {
			credential := func(purpose, scope string) contracts.SeaweedCredential {
				c, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: scope})
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			admin := credential("admin", swSetupID("1"))
			original, err := providerconfig.CompileSeaweedStorage(admin, []contracts.SeaweedGrant{{Credential: credential("initial-audit", swSetupID("9")), InstallationID: swSetupID("9"), Bucket: "audit"}})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(original.Config)
			added, err := providerconfig.CompileSeaweedStorage(admin, []contracts.SeaweedGrant{{Credential: credential("regional-write", swSetupID("8")), InstallationID: swSetupID("9"), ClusterID: swSetupID("8"), Bucket: "audit"}})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(added.Config)
			claim := contracts.SeaweedBucketInitialization{BackendID: swSetupID("1"), InstallationID: swSetupID("9"), InitializationID: swSetupID("2"), StateSecretUID: swSetupID("3"), PVCUID: swSetupID("4"), Image: "chrislusf/seaweedfs@sha256:" + strings.Repeat("a", 64), Bucket: "audit"}
			policy := string(original.Policies["audit"])
			before, _ := seaweedPolicyStatements([]byte(policy))
			additions := added.Policies["audit"]
			if mode == "conflict" {
				var d struct {
					Version   string           `json:"Version"`
					Statement []map[string]any `json:"Statement"`
				}
				_ = json.Unmarshal([]byte(policy), &d)
				d.Statement[0]["Effect"] = "Allow"
				additions, _ = json.Marshal(d)
			}
			if mode == "pending" {
				claim.Pending = true
			}
			puts, otherWrites := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if r.Method != http.MethodGet && !(q.Has("policy") && r.Method == http.MethodPut) {
					otherWrites++
					w.WriteHeader(400)
					return
				}
				switch {
				case q.Has("tagging"):
					w.Header().Set("Content-Type", "application/xml")
					_, _ = io.WriteString(w, "<Tagging><TagSet>")
					for _, tag := range seaweedOwnership(claim) {
						value := aws.ToString(tag.Value)
						if mode == "foreign-tags" {
							value = "foreign"
						}
						_, _ = io.WriteString(w, "<Tag><Key>"+aws.ToString(tag.Key)+"</Key><Value>"+value+"</Value></Tag>")
					}
					_, _ = io.WriteString(w, "</TagSet></Tagging>")
				case q.Has("versioning"):
					state := "Enabled"
					if mode == "suspended" {
						state = "Suspended"
					}
					_, _ = io.WriteString(w, "<VersioningConfiguration><Status>"+state+"</Status></VersioningConfiguration>")
				case q.Has("policy"):
					if r.Method == http.MethodPut {
						puts++
						raw, _ := io.ReadAll(io.LimitReader(r.Body, providerconfig.SeaweedConfigLimit+1))
						policy = string(raw)
						if mode == "unknown-put" && puts == 1 {
							w.Header().Set("Content-Type", "application/xml")
							w.WriteHeader(500)
							_, _ = io.WriteString(w, "<Error><Code>InternalError</Code></Error>")
							return
						}
					}
					_, _ = io.WriteString(w, policy)
				default:
					t.Error("unexpected storage API")
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			claim.Endpoint = server.URL
			setup, err := NewSeaweedSetup(server.URL, "test", admin, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer setup.Close()
			ctx, end := context.WithCancel(t.Context())
			defer end()
			err = setup.AppendBucketPolicy(ctx, claim, additions)
			if mode != "append" {
				if err == nil {
					t.Fatal("unsafe append accepted")
				}
				expectedWrites := 0
				if mode == "unknown-put" {
					expectedWrites = 1
				}
				if puts != expectedWrites || otherWrites != 0 {
					t.Fatal("failed append retried or changed bucket metadata", puts, otherWrites)
				}
				if mode != "unknown-put" {
					return
				}
			}
			if mode == "append" && err != nil {
				t.Fatal(err)
			}
			after, err := seaweedPolicyStatements([]byte(policy))
			if err != nil {
				t.Fatal(err)
			}
			for sid, statement := range before {
				if !sameSeaweedJSON(statement, after[sid]) {
					t.Fatal("original policy SID or contents changed")
				}
			}
			extra, _ := seaweedPolicyStatements(additions)
			if len(after) != len(before)+len(extra) {
				t.Fatal("not all additions present")
			}
			if err = setup.AppendBucketPolicy(ctx, claim, additions); err != nil || puts != 1 || otherWrites != 0 {
				t.Fatal("exact replay failed or performed another mutation", err, puts, otherWrites)
			}
			end()
			if setup.AppendBucketPolicy(ctx, claim, additions) == nil || puts != 1 {
				t.Fatal("canceled append admitted")
			}
		})
	}
}
