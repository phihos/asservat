package objectstore

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
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

// fakeSeaweedBucket is one bucket of the in-memory S3 fake.
type fakeSeaweedBucket struct {
	tags            []types.Tag
	version, policy string
	objects         bool
}

// fakeSeaweed serves the bucket administration subset setup uses. It counts
// mutating requests and can fail the first create with an unknown reply.
type fakeSeaweed struct {
	t             *testing.T
	buckets       map[string]*fakeSeaweedBucket
	writes        int
	unknownCreate bool
	normalize     bool
}

func (f *fakeSeaweed) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	q := r.URL.Query()
	name := strings.Trim(r.URL.Path, "/")
	fail := func(code string) {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "<Error><Code>"+code+"</Code></Error>")
	}
	b := f.buckets[name]
	if r.Method == http.MethodPut && len(q) == 0 {
		f.writes++
		if b == nil {
			f.buckets[name] = &fakeSeaweedBucket{}
		}
		if f.unknownCreate {
			f.unknownCreate = false
			w.WriteHeader(500)
			_, _ = io.WriteString(w, "<Error><Code>InternalError</Code></Error>")
		}
		return
	}
	if b == nil {
		fail("NoSuchBucket")
		return
	}
	switch {
	case q.Has("tagging"):
		if r.Method == http.MethodPut {
			f.writes++
			var doc struct {
				TagSet []struct {
					Key   string `xml:"Key"`
					Value string `xml:"Value"`
				} `xml:"TagSet>Tag"`
			}
			if xml.NewDecoder(r.Body).Decode(&doc) != nil {
				f.t.Error("tag body")
			}
			b.tags = nil
			for _, tag := range doc.TagSet {
				b.tags = append(b.tags, types.Tag{Key: aws.String(tag.Key), Value: aws.String(tag.Value)})
			}
			return
		}
		if len(b.tags) == 0 {
			fail("NoSuchTagSet")
			return
		}
		_, _ = io.WriteString(w, "<Tagging><TagSet>")
		for _, tag := range b.tags {
			_, _ = io.WriteString(w, "<Tag><Key>"+aws.ToString(tag.Key)+"</Key><Value>"+aws.ToString(tag.Value)+"</Value></Tag>")
		}
		_, _ = io.WriteString(w, "</TagSet></Tagging>")
	case q.Has("versioning"):
		if r.Method == http.MethodPut {
			f.writes++
			b.version = "Enabled"
			return
		}
		_, _ = io.WriteString(w, "<VersioningConfiguration><Status>"+b.version+"</Status></VersioningConfiguration>")
	case q.Has("policy"):
		if r.Method == http.MethodPut {
			f.writes++
			raw, _ := io.ReadAll(io.LimitReader(r.Body, providerconfig.SeaweedConfigLimit+1))
			b.policy = string(raw)
			w.WriteHeader(204)
			return
		}
		if b.policy == "" {
			fail("NoSuchBucketPolicy")
			return
		}
		if f.normalize {
			_, _ = io.WriteString(w, seaweedProviderPolicyRoundTrip(f.t, b.policy))
		} else {
			_, _ = io.WriteString(w, b.policy)
		}
	case q.Has("versions"):
		_, _ = io.WriteString(w, "<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>")
	case q.Has("uploads"):
		_, _ = io.WriteString(w, "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>")
	case q.Get("list-type") == "2":
		body := "<ListBucketResult><IsTruncated>false</IsTruncated>"
		if b.objects {
			body += "<Contents><Key>managed</Key><Size>1</Size></Contents>"
		}
		_, _ = io.WriteString(w, body+"</ListBucketResult>")
	default:
		f.t.Errorf("unexpected setup operation %s %s", r.Method, r.URL)
		w.WriteHeader(500)
	}
}

func TestEnsureSetupBuckets(t *testing.T) {
	installation := swSetupID("9")
	admin, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "admin", ScopeID: swSetupID("1")})
	if e != nil {
		t.Fatal(e)
	}
	key, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "initial-audit", ScopeID: installation})
	if e != nil {
		t.Fatal(e)
	}
	compiled, e := providerconfig.CompileSeaweedStorage(admin, []contracts.SeaweedGrant{{Credential: key, Bucket: "audit", InstallationID: installation}})
	if e != nil {
		t.Fatal(e)
	}
	defer clear(compiled.Config)
	owned := func(bucket string) []types.Tag {
		return seaweedOwnership(contracts.SeaweedBucketInitialization{InstallationID: installation, Bucket: bucket})
	}
	for _, mode := range []string{"fresh", "unknown-create", "normalized-policy", "untagged-empty", "foreign-installation", "untagged-nonempty", "policy-replacement"} {
		t.Run(mode, func(t *testing.T) {
			f := &fakeSeaweed{t: t, buckets: map[string]*fakeSeaweedBucket{}, unknownCreate: mode == "unknown-create", normalize: mode == "normalized-policy"}
			switch mode {
			case "untagged-empty":
				f.buckets["audit"] = &fakeSeaweedBucket{}
			case "foreign-installation":
				f.buckets["audit"] = &fakeSeaweedBucket{tags: seaweedOwnership(contracts.SeaweedBucketInitialization{InstallationID: swSetupID("8"), Bucket: "audit"}), version: "Enabled"}
			case "untagged-nonempty":
				f.buckets["audit"] = &fakeSeaweedBucket{objects: true}
			case "policy-replacement":
				f.buckets["audit"] = &fakeSeaweedBucket{tags: owned("audit"), version: "Enabled", policy: `{"Version":"2012-10-17","Statement":[{"Sid":"AsservatForeign","Effect":"Deny","Resource":"*"}]}`}
			}
			server := httptest.NewTLSServer(f)
			defer server.Close()
			roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			run := func() error {
				var out bytes.Buffer
				return EnsureSetupBuckets(context.Background(), server.URL, "test", roots, admin, installation, []string{"evidence", "audit"}, compiled.Policies, &out)
			}
			e := run()
			refused := mode == "foreign-installation" || mode == "untagged-nonempty" || mode == "policy-replacement"
			if refused {
				if e == nil {
					t.Fatal("foreign or nonempty bucket accepted")
				}
				if mode != "policy-replacement" && f.writes != 0 {
					t.Fatalf("refused bucket mutated: writes=%d", f.writes)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			for _, name := range []string{"audit", "evidence"} {
				b := f.buckets[name]
				if b == nil || !sameSeaweedTags(b.tags, owned(name)) || b.version != "Enabled" {
					t.Fatalf("bucket %s not configured: %+v", name, b)
				}
			}
			if !sameSeaweedJSON([]byte(f.buckets["audit"].policy), compiled.Policies["audit"]) || f.buckets["evidence"].policy != "" {
				t.Fatal("bucket policies not applied as compiled")
			}
			previous := f.writes
			if e = run(); e != nil || f.writes != previous {
				t.Fatalf("rerun not idempotent: err=%v writes=%d->%d", e, previous, f.writes)
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
