package objectstore

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func swSetupID(n string) string { return "10000000-0000-4000-8000-00000000000" + n }
func TestSeaweedSetupPendingReopenAndRetainedRefusal(t *testing.T) {
	for _, mode := range []string{"empty-pending", "unknown-create", "foreign", "nonempty", "not-pending", "suspended", "policy-replacement", "wrong-backend", "wrong-installation", "normalized-policy"} {
		t.Run(mode, func(t *testing.T) {
			admin, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "admin", ScopeID: swSetupID("1")})
			if e != nil {
				t.Fatal(e)
			}
			key, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "initial-audit", ScopeID: swSetupID("9")})
			if e != nil {
				t.Fatal(e)
			}
			compiled, e := providerconfig.CompileSeaweedStorage(admin, []contracts.SeaweedGrant{{Credential: key, Bucket: "audit", InstallationID: swSetupID("9")}})
			if e != nil {
				t.Fatal(e)
			}

			if mode == "normalized-policy" {
				extra, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "evidence-delete", ScopeID: swSetupID("9")})
				if e != nil {
					t.Fatal(e)
				}
				clear(compiled.Config)
				compiled, e = providerconfig.CompileSeaweedStorage(admin, []contracts.SeaweedGrant{{Credential: key, Bucket: "audit", InstallationID: swSetupID("9")}, {Credential: extra, Bucket: "audit", InstallationID: swSetupID("9")}})
				if e != nil {
					t.Fatal(e)
				}
			}
			defer clear(compiled.Config)
			claim := contracts.SeaweedBucketInitialization{BackendID: swSetupID("1"), InstallationID: swSetupID("9"), InitializationID: swSetupID("2"), StateSecretUID: swSetupID("3"), PVCUID: swSetupID("4"), Image: "chrislusf/seaweedfs@sha256:" + strings.Repeat("a", 64), Bucket: "audit", Pending: true}
			var tags []types.Tag
			version := ""
			policy := ""
			writes, emptyReads := 0, 0
			missing := mode == "unknown-create"
			if mode == "wrong-backend" {
				claim.BackendID = swSetupID("8")
			}
			if mode == "wrong-installation" {
				tags = seaweedOwnership(claim)
				claim.InstallationID = swSetupID("8")
				claim.Pending = false
			}
			if mode == "foreign" {
				tags = []types.Tag{{Key: aws.String("foreign"), Value: aws.String("other")}}
			}
			if mode == "not-pending" {
				claim.Pending = false
			}
			if mode == "suspended" || mode == "policy-replacement" {
				tags = seaweedOwnership(claim)
				claim.Pending = false
			}
			if mode == "policy-replacement" {
				version = "Enabled"
				policy = `{"Version":"2012-10-17","Statement":[{"Sid":"AsservatForeign","Effect":"Deny","Resource":"*"}]}`
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				q := r.URL.Query()
				if r.URL.Path != "/audit" && r.URL.Path != "/audit/" {
					t.Errorf("unexpected bucket path %s", r.URL.Path)
				}
				fail := func(code string) {
					w.WriteHeader(404)
					_, _ = io.WriteString(w, "<Error><Code>"+code+"</Code></Error>")
				}
				switch {
				case q.Has("tagging"):
					if r.Method == http.MethodPut {
						writes++
						var doc struct {
							TagSet []struct {
								Key   string `xml:"Key"`
								Value string `xml:"Value"`
							} `xml:"TagSet>Tag"`
						}
						if xml.NewDecoder(r.Body).Decode(&doc) != nil {
							t.Error("tag body")
						}
						tags = nil
						for _, tag := range doc.TagSet {
							tags = append(tags, types.Tag{Key: aws.String(tag.Key), Value: aws.String(tag.Value)})
						}
					}
					if missing {
						fail("NoSuchBucket")
						return
					}
					if len(tags) == 0 {
						fail("NoSuchTagSet")
						return
					}
					_, _ = io.WriteString(w, "<Tagging><TagSet>")
					for _, tag := range tags {
						_, _ = io.WriteString(w, "<Tag><Key>"+aws.ToString(tag.Key)+"</Key><Value>"+aws.ToString(tag.Value)+"</Value></Tag>")
					}
					_, _ = io.WriteString(w, "</TagSet></Tagging>")
				case q.Has("versioning"):
					if r.Method == http.MethodPut {
						writes++
						version = "Enabled"
					}
					_, _ = io.WriteString(w, "<VersioningConfiguration><Status>"+version+"</Status></VersioningConfiguration>")
				case q.Has("policy"):
					if r.Method == http.MethodPut {
						writes++
						raw, _ := io.ReadAll(io.LimitReader(r.Body, providerconfig.SeaweedConfigLimit+1))
						policy = string(raw)
					}
					if policy == "" {
						fail("NoSuchBucketPolicy")
						return
					}
					if mode == "normalized-policy" {
						_, _ = io.WriteString(w, seaweedProviderPolicyRoundTrip(t, policy))
					} else {
						_, _ = io.WriteString(w, policy)
					}
				case q.Has("list-type"):
					emptyReads++
					body := "<ListBucketResult><IsTruncated>false</IsTruncated>"
					if mode == "nonempty" {
						body += "<Contents><Key>managed</Key><Size>1</Size></Contents>"
					}
					_, _ = io.WriteString(w, body+"</ListBucketResult>")
				case q.Has("versions"):
					emptyReads++
					_, _ = io.WriteString(w, "<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>")
				case q.Has("uploads"):
					emptyReads++
					_, _ = io.WriteString(w, "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>")
				case r.Method == http.MethodPut && mode == "unknown-create":
					writes++
					missing = false
					w.WriteHeader(500)
					_, _ = io.WriteString(w, "<Error><Code>InternalError</Code></Error>")
				default:
					t.Error("unexpected setup operation")
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			claim.Endpoint = server.URL
			setup, e := NewSeaweedSetup(server.URL, "test", admin, server.Client())
			if e != nil {
				t.Fatal(e)
			}
			defer setup.Close()
			e = setup.ConfigureBucket(context.Background(), claim, compiled.Policies["audit"])
			success := mode == "empty-pending" || mode == "unknown-create" || mode == "normalized-policy"
			if success {
				if e != nil || emptyReads != 3 {
					t.Fatalf("empty owned first-init failed: err=%v scans=%d", e, emptyReads)
				}
				previous := writes
				claim.Pending = false
				if e = setup.ConfigureBucket(context.Background(), claim, compiled.Policies["audit"]); e != nil || writes != previous || emptyReads != 3 {
					t.Fatalf("retained replay wrote or inventoried data: err=%v writes=%d", e, writes)
				}
			} else if e == nil || writes != 0 {
				t.Fatalf("foreign/nonempty/changed setup accepted or mutated: err=%v writes=%d", e, writes)
			}
		})
	}
}
func TestSeaweedPolicyExtensionPreservesEveryRetainedStatement(t *testing.T) {
	old := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Sid":"AsservatOne","Effect":"Deny","Action":["s3:DeleteObject"],"Resource":"arn:aws:s3:::audit/*"}]}`)
	next := json.RawMessage(`{"Statement":[{"Resource":"arn:aws:s3:::audit/*","Action":["s3:DeleteObject"],"Effect":"Deny","Sid":"AsservatOne"},{"Sid":"AsservatTwo","Effect":"Deny"}],"Version":"2012-10-17"}`)
	if !seaweedPolicyExtends(old, next) || seaweedPolicyExtends(next, old) || seaweedPolicyExtends(old, []byte(strings.ReplaceAll(string(old), "Deny", "Allow"))) {
		t.Fatal("retained policy replacement boundary changed")
	}
	unknown := []byte(strings.Replace(string(old), `"Effect":"Deny"`, `"Effect":"Deny","NotAction":"s3:*"`, 1))
	if sameSeaweedJSON(old, unknown) || seaweedPolicyExtends(unknown, old) {
		t.Fatal("unknown retained policy field ignored")
	}
	scoped := []byte(strings.ReplaceAll(string(old), "audit/*", "*"))
	if sameSeaweedJSON(old, scoped) || seaweedPolicyExtends(scoped, old) {
		t.Fatal("changed resource boundary ignored")
	}

}

// Mirrors only the exact pinned upstream StringOrStringSlice JSON behavior;
// principal object shape and every statement/condition key remain unchanged.
func seaweedProviderPolicyRoundTrip(t *testing.T, raw string) string {
	t.Helper()
	var doc map[string]any
	if json.Unmarshal([]byte(raw), &doc) != nil {
		t.Fatal("synthetic policy")
	}
	one := func(value any) any {
		if a, ok := value.([]any); ok && len(a) == 1 {
			return a[0]
		}
		return value
	}
	for _, value := range doc["Statement"].([]any) {
		s := value.(map[string]any)
		s["Action"] = one(s["Action"])
		s["Resource"] = one(s["Resource"])
		if condition, ok := s["Condition"].(map[string]any); ok {
			for _, keys := range condition {
				for key, v := range keys.(map[string]any) {
					keys.(map[string]any)[key] = one(v)
				}
			}
		}
	}
	encoded, e := json.Marshal(doc)
	if e != nil {
		t.Fatal("synthetic policy encoding")
	}
	return string(encoded)
}
