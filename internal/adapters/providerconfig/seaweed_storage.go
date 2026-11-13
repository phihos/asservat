package providerconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

const SeaweedConfigKey = "s3.json"
const SeaweedConfigLimit = 768 << 10 // Below the existing Kubernetes Secret data limit.
var ErrSeaweedStorage = errors.New("bundled object store configuration unavailable")
var seaweedBucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var seaweedPurposes = []string{"admin", "initial-audit", "configuration-audit", "owner-audit", "federation-audit", "publisher-audit", "publisher-read", "download-read", "evidence-delete", "operation-cleanup", "operation-verify", "regional-write", "regional-history"}

func SeaweedPrincipalName(k contracts.SeaweedPrincipalKey) (string, error) {
	if !slices.Contains(seaweedPurposes, k.Purpose) || !authorization.UUID(k.ScopeID) {
		return "", ErrSeaweedStorage
	}
	return "asservat-" + k.Purpose + "-" + k.ScopeID, nil
}
func GenerateSeaweedCredential(k contracts.SeaweedPrincipalKey) (contracts.SeaweedCredential, error) {
	if _, err := SeaweedPrincipalName(k); err != nil {
		return contracts.SeaweedCredential{}, err
	}
	credential, err := GenerateSeaweedStorageCredential()
	if err != nil {
		return contracts.SeaweedCredential{}, ErrSeaweedStorage
	}
	return contracts.SeaweedCredential{Principal: k, AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey}, nil
}
func ValidateSeaweedCredential(c contracts.SeaweedCredential) error {
	if _, err := SeaweedPrincipalName(c.Principal); err != nil || len(c.AccessKeyID) != 43 || !strings.HasPrefix(c.AccessKeyID, "ASV") || len(c.SecretAccessKey) != 64 {
		return ErrSeaweedStorage
	}
	for _, s := range []string{c.AccessKeyID[3:], c.SecretAccessKey} {
		raw, err := hex.DecodeString(s)
		if err != nil || hex.EncodeToString(raw) != s {
			return ErrSeaweedStorage
		}
		clear(raw)
	}
	return nil
}

type seaweedIdentity struct {
	Name        string       `json:"name"`
	Credentials []seaweedKey `json:"credentials"`
	Actions     []string     `json:"actions"`
}
type seaweedKey struct {
	Access string `json:"accessKey"`
	Secret string `json:"secretKey"`
}
type seaweedPolicy struct {
	Version   string           `json:"Version"`
	Statement []map[string]any `json:"Statement"`
}
type CompiledSeaweedStorage struct {
	// Config contains private credentials. Never print it or put it in values,
	// ConfigMaps, annotations, diagnostics, digests or Helm release metadata.
	Config   []byte
	Policies map[string]json.RawMessage
}

// CompileSeaweedStorage compiles a COMPLETE retained identity set. Callers keep
// old entries on later phases; this function neither invents keys nor merges
// untrusted provider state. Actual IAM/version/conditional behavior needs the
// separately qualified exact Seaweed version.
func CompileSeaweedStorage(admin contracts.SeaweedCredential, grants []contracts.SeaweedGrant) (CompiledSeaweedStorage, error) {
	zero := CompiledSeaweedStorage{}
	if ValidateSeaweedCredential(admin) != nil || admin.Principal.Purpose != "admin" || len(grants) > 4096 {
		return zero, ErrSeaweedStorage
	}
	name, _ := SeaweedPrincipalName(admin.Principal)
	identities := []seaweedIdentity{{Name: name, Credentials: []seaweedKey{{admin.AccessKeyID, admin.SecretAccessKey}}, Actions: []string{"Admin", "Read", "Write", "List"}}}
	names := map[string]bool{name: true}
	keys := map[string]bool{admin.AccessKeyID: true}
	policies := map[string]seaweedPolicy{}
	installation := ""
	ordered := slices.Clone(grants)
	slices.SortFunc(ordered, func(a, b contracts.SeaweedGrant) int {
		na, _ := SeaweedPrincipalName(a.Credential.Principal)
		nb, _ := SeaweedPrincipalName(b.Credential.Principal)
		return strings.Compare(na, nb)
	})
	for _, grant := range ordered {
		actions, statements, err := seaweedGrant(grant)
		if err != nil {
			return zero, err
		}
		credential := grant.Credential
		principal, _ := SeaweedPrincipalName(credential.Principal)
		if installation == "" {
			installation = grant.InstallationID
		}
		if names[principal] || keys[credential.AccessKeyID] || grant.InstallationID != installation {
			return zero, ErrSeaweedStorage
		}
		names[principal], keys[credential.AccessKeyID] = true, true
		identities = append(identities, seaweedIdentity{Name: principal, Credentials: []seaweedKey{{credential.AccessKeyID, credential.SecretAccessKey}}, Actions: actions})
		policy := policies[grant.Bucket]
		policy.Version = "2012-10-17"
		policy.Statement = append(policy.Statement, statements...)
		policies[grant.Bucket] = policy
	}
	raw, err := json.Marshal(struct {
		Identities []seaweedIdentity `json:"identities"`
	}{identities})
	if err != nil || len(raw) > SeaweedConfigLimit {
		clear(raw)
		return zero, ErrSeaweedStorage
	}
	out := CompiledSeaweedStorage{Config: raw, Policies: map[string]json.RawMessage{}}
	for bucket, policy := range policies {
		b, err := json.Marshal(policy)
		if err != nil || len(b) > SeaweedConfigLimit {
			clear(out.Config)
			return zero, ErrSeaweedStorage
		}
		out.Policies[bucket] = b
	}
	return out, nil
}

func seaweedGrant(g contracts.SeaweedGrant) ([]string, []map[string]any, error) {
	if ValidateSeaweedCredential(g.Credential) != nil || g.Credential.Principal.Purpose == "admin" || !authorization.UUID(g.InstallationID) || !seaweedBucket.MatchString(g.Bucket) || strings.Contains(g.Bucket, "..") || len(g.Prefixes) > 32 {
		return nil, nil, ErrSeaweedStorage
	}
	for _, id := range []string{g.ClusterID, g.RootID, g.SourceUID} {
		if id != "" && !authorization.UUID(id) {
			return nil, nil, ErrSeaweedStorage
		}
	}
	purpose := g.Credential.Principal.Purpose
	regional := purpose == "regional-write" || purpose == "regional-history"
	if regional && g.Credential.Principal.ScopeID != g.ClusterID || !regional && g.Credential.Principal.ScopeID != g.InstallationID {
		return nil, nil, ErrSeaweedStorage
	}
	prefixes, read, write, list, err := seaweedScope(g)
	if err != nil {
		return nil, nil, err
	}
	var actions []string
	for _, prefix := range prefixes {
		if read {
			actions = append(actions, "Read:"+g.Bucket+"/"+prefix+"*")
		}
		if write {
			actions = append(actions, "Write:"+g.Bucket+"/"+prefix+"*")
		}
	}
	if list {
		actions = append(actions, "List:"+g.Bucket)
	}
	principal, _ := SeaweedPrincipalName(g.Credential.Principal)
	resource := "arn:aws:s3:::" + g.Bucket
	subject := map[string]any{"AWS": "arn:aws:iam::000000000000:user/" + principal}
	hash := sha256.Sum256([]byte(principal))
	sid := "Asservat" + hex.EncodeToString(hash[:12])
	statement := func(suffix, effect string, verbs []string, target any, condition any) map[string]any {
		if resources, ok := target.([]string); ok {
			target = seaweedPolicyStrings(resources)
		}
		m := map[string]any{"Sid": sid + suffix, "Effect": effect, "Principal": subject, "Action": seaweedPolicyStrings(verbs), "Resource": target}
		if condition != nil {
			m["Condition"] = condition
		}
		return m
	}
	adminOps := []string{"s3:PutBucketTagging", "s3:DeleteBucketTagging", "s3:PutBucketVersioning", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutLifecycleConfiguration", "s3:PutBucketAcl", "s3:DeleteBucket", "s3:PutBucketObjectLockConfiguration", "s3:PutObjectRetention", "s3:PutObjectLegalHold"}
	statements := []map[string]any{statement("Administration", "Deny", adminOps, []string{resource, resource + "/*"}, nil)}
	resources := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		resources[i] = resource + "/" + prefix + "*"
	}
	if list {
		patterns := make([]string, len(prefixes))
		for i, prefix := range prefixes {
			patterns[i] = prefix + "*"
		}
		ops := []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"}
		statements = append(statements, statement("Inventory", "Allow", ops, resource, map[string]any{"StringLike": map[string]any{"s3:prefix": seaweedPolicyStrings(patterns)}}), statement("ForeignInventory", "Deny", ops, resource, map[string]any{"StringNotLike": map[string]any{"s3:prefix": seaweedPolicyStrings(patterns)}}))
	}
	switch purpose {
	case "evidence-delete":
		statements = append(statements, statement("Delete", "Allow", []string{"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload"}, resources, nil), statement("Read", "Deny", []string{"s3:GetObject", "s3:GetObjectVersion"}, resource+"/*", nil), statement("Write", "Deny", []string{"s3:PutObject"}, resource+"/*", map[string]any{"StringNotEquals": map[string]any{"s3:RequestMethod": "DELETE"}}))
	case "operation-cleanup":
		statements = append(statements, statement("Delete", "Allow", []string{"s3:DeleteObjectVersion", "s3:AbortMultipartUpload"}, resources, nil), statement("Certificate", "Allow", []string{"s3:PutObject"}, resource+"/"+prefixes[0]+"*/deletion-certificate", nil))
	case "regional-history":
		statements = append(statements, statement("History", "Allow", []string{"s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"}, resources, nil), statement("Evidence", "Deny", []string{"s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"}, resource+"/v1/*", nil))
	default:
		denied := []string{"s3:DeleteObject", "s3:DeleteObjectVersion"}
		if !write {
			denied = append(denied, "s3:PutObject", "s3:AbortMultipartUpload")
		}
		statements = append(statements, statement("Mutation", "Deny", denied, resource+"/*", nil))
	}
	return actions, statements, nil
}

// Match the pinned provider's policy StringOrStringSlice wire encoding. This
// changes construction only; strict policy readback/retained equality stays intact.
func seaweedPolicyStrings(values []string) any {
	if len(values) == 1 {
		return values[0]
	}
	return values
}

func seaweedScope(g contracts.SeaweedGrant) (prefixes []string, read, write, list bool, err error) {
	fail := func() ([]string, bool, bool, bool, error) { return nil, false, false, false, ErrSeaweedStorage }
	purpose := g.Credential.Principal.Purpose
	switch purpose {
	case "initial-audit":
		prefixes = []string{"initial-installation/v1/" + g.InstallationID + "/"}
		read, write = true, true
	case "publisher-read", "download-read":
		prefixes = []string{"v1/"}
		read = true
	case "evidence-delete":
		prefixes = []string{"v1/"}
		list = true
	case "operation-cleanup", "operation-verify":
		if !authorization.UUID(g.RootID) {
			return fail()
		}
		prefixes = []string{"operation-audit/v1/" + g.RootID + "/"}
		read, list = true, true
	case "regional-write":
		if !authorization.UUID(g.ClusterID) {
			return fail()
		}
		prefixes = []string{"v1/" + g.ClusterID + "/"}
		write = true
	case "regional-history":
		if !authorization.UUID(g.ClusterID) || !authorization.UUID(g.RootID) {
			return fail()
		}
		prefixes = []string{"history/v1/" + g.RootID + "/" + g.ClusterID + "/"}
		read, write, list = true, true, true
	case "configuration-audit", "owner-audit", "federation-audit", "publisher-audit":
		allowed := seaweedAuditPrefixes(g)
		if len(g.Prefixes) == 0 {
			return fail()
		}
		for _, prefix := range g.Prefixes {
			if !slices.Contains(allowed, prefix) || slices.Contains(prefixes, prefix) {
				return fail()
			}
			prefixes = append(prefixes, prefix)
		}
		read, write = true, true
	default:
		return fail()
	}
	if len(g.Prefixes) > 0 && (!strings.HasSuffix(purpose, "-audit") || purpose == "initial-audit") {
		return fail()
	}
	slices.Sort(prefixes)
	return prefixes, read, write, list, nil
}
func seaweedAuditPrefixes(g contracts.SeaweedGrant) []string {
	i, c, r, s := g.InstallationID, g.ClusterID, g.RootID, g.SourceUID
	switch g.Credential.Principal.Purpose {
	case "configuration-audit":
		p := []string{"authority/v1/", "retention-acceptance/v1/", "lifecycle/v1/", "context-deletion/v1/", "download-worker-configuration/v1/" + i + "/"}
		if c != "" && s != "" {
			p = append(p, "hub-owner-configuration/v1/"+i+"/"+c+"/"+s+"/")
		}
		return p
	case "owner-audit":
		p := []string{"hub-owner-enrollment/v1/" + i + "/", "hub-owner-certificate/v1/" + i + "/", "download-worker-enrollment/v1/" + i + "/", "download-worker-certificate/v1/" + i + "/", "acquisition-enrollment/v1/native-download/" + i + "/", "acquisition-enrollment/v1/approved-pod-status/" + i + "/", "acquisition-certificate/v1/native-download/" + i + "/", "acquisition-certificate/v1/approved-pod-status/" + i + "/", "bootstrap-issue/v1/" + i + "/"}
		if r != "" {
			for _, kind := range []string{"operation-audit", "capture-intent", "download-audit", "download-worker-audit", "download-window-audit", "download-stop", "context-query-worker", "policy-acceptance"} {
				p = append(p, kind+"/v1/"+r+"/")
			}
		}
		return p
	case "federation-audit":
		p := []string{"enrollment-claim/v1/" + i + "/", "cluster-bootstrap/v1/" + i + "/"}
		if r != "" {
			p = append(p, "operation-audit/v1/"+r+"/")
		}
		return p
	case "publisher-audit":
		if r != "" {
			return []string{"context-verification/v1/" + r + "/"}
		}
	}
	return nil
}

// SeaweedRuntimeCredential deliberately refuses the provider administrator.
func SeaweedRuntimeCredential(c contracts.SeaweedCredential) (contracts.OwnerStorageCredential, error) {
	if ValidateSeaweedCredential(c) != nil || c.Principal.Purpose == "admin" {
		return contracts.OwnerStorageCredential{}, ErrSeaweedStorage
	}
	return contracts.OwnerStorageCredential{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey}, nil
}

func decodeSeaweedIdentities(raw []byte) (map[string]seaweedIdentity, error) {
	if len(raw) == 0 || len(raw) > SeaweedConfigLimit {
		return nil, ErrSeaweedStorage
	}
	var doc struct {
		Identities []seaweedIdentity `json:"identities"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&doc) != nil || d.Decode(new(any)) != io.EOF || len(doc.Identities) == 0 || len(doc.Identities) > 4097 {
		return nil, ErrSeaweedStorage
	}
	out := map[string]seaweedIdentity{}
	keys := map[string]bool{}
	admins := 0
	for _, id := range doc.Identities {
		if len(id.Name) < 46 || !strings.HasPrefix(id.Name, "asservat-") || len(id.Credentials) != 1 || len(id.Actions) == 0 || len(id.Actions) > 65 || out[id.Name].Name != "" {
			return nil, ErrSeaweedStorage
		}
		suffix := len(id.Name) - 36
		k := contracts.SeaweedPrincipalKey{Purpose: id.Name[len("asservat-") : suffix-1], ScopeID: id.Name[suffix:]}
		name, e := SeaweedPrincipalName(k)
		if e != nil || name != id.Name {
			return nil, ErrSeaweedStorage
		}
		key := id.Credentials[0]
		if ValidateSeaweedCredential(contracts.SeaweedCredential{Principal: k, AccessKeyID: key.Access, SecretAccessKey: key.Secret}) != nil || keys[key.Access] {
			return nil, ErrSeaweedStorage
		}
		keys[key.Access] = true
		if k.Purpose == "admin" {
			admins++
			if !slices.Equal(id.Actions, []string{"Admin", "Read", "Write", "List"}) {
				return nil, ErrSeaweedStorage
			}
		} else {
			for _, action := range id.Actions {
				if !(strings.HasPrefix(action, "Read:") || strings.HasPrefix(action, "Write:") || strings.HasPrefix(action, "List:")) || strings.ContainsAny(action, "\r\n") {
					return nil, ErrSeaweedStorage
				}
			}
		}
		out[id.Name] = id
	}
	if admins != 1 {
		return nil, ErrSeaweedStorage
	}
	return out, nil
}

// ValidateSeaweedConfigTransition prevents later installer phases from replacing
// or dropping a retained principal/key/capability. Inputs remain private. It is
// not a replacement for CompileSeaweedStorage's purpose/recipe checks.
func ValidateSeaweedConfigTransition(before, after []byte) error {
	old, e := decodeSeaweedIdentities(before)
	if e != nil {
		return e
	}
	next, e := decodeSeaweedIdentities(after)
	if e != nil {
		return e
	}
	for name, identity := range old {
		n, ok := next[name]
		if !ok || !slices.Equal(identity.Credentials, n.Credentials) {
			return ErrSeaweedStorage
		}
		for _, a := range identity.Actions {
			if !slices.Contains(n.Actions, a) {
				return ErrSeaweedStorage
			}
		}
	}
	return nil
}

// SeaweedServerArgs is the reviewed single-process listener/storage contract.
// The Helm render regression compares the actual chart command to this value.
func SeaweedServerArgs() []string {
	return []string{
		"server", "-dir=/data", "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-master=true", "-volume=true", "-filer=true", "-s3=true", "-master.telemetry=false", "-s3.ip.bind=0.0.0.0", "-s3.port=8333", "-s3.port.https=0", "-s3.cert.file=/run/asservat/objectstore-tls/tls.crt", "-s3.key.file=/run/asservat/objectstore-tls/tls.key", "-s3.config=/run/asservat/objectstore-iam/s3.json", "-s3.iam=false", "-s3.autoCreateBucket=false", "-s3.port.iceberg=0", "-s3.port.lance=0", "-iam=false", "-webdav=false", "-sftp=false", "-mq.broker=false", "-mq.agent=false", "-metricsPort=0", "-debug=false",
	}
}
