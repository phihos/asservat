package providerconfig

import "encoding/json"

// InitialProviderPolicyBodies is the shared pure initial-audit ACL compiler.
// Bootstrap generation and runtime inspection consume identical policy bytes.
// It creates no provider object or credential and grants no authority.
type initialProviderACLRule struct {
	Capabilities []string `json:"capabilities"`
}
type initialProviderACL struct {
	Path map[string]initialProviderACLRule `json:"path"`
}

func InitialProviderPolicyBodies(issuerPolicy, wrapRole, wrapPolicy, unwrapRole, unwrapPolicy, mount, key string) (map[string]string, error) {
	if !InitialProviderNames(issuerPolicy, wrapRole, wrapPolicy, unwrapRole, unwrapPolicy) || !providerName.MatchString(mount) || !providerName.MatchString(key) {
		return nil, ErrSetupUnavailable
	}
	paths := map[string]initialProviderACLRule{"auth/token/lookup-self": {[]string{"read"}}, "auth/token/lookup-accessor": {[]string{"update"}}, "auth/token/revoke-accessor": {[]string{"update"}}}
	for _, role := range []string{wrapRole, unwrapRole} {
		paths["auth/token/roles/"+role] = initialProviderACLRule{[]string{"read"}}
		paths["auth/token/create/"+role] = initialProviderACLRule{[]string{"update"}}
	}
	for _, policy := range []string{issuerPolicy, wrapPolicy, unwrapPolicy} {
		paths["sys/policies/acl/"+policy] = initialProviderACLRule{[]string{"read"}}
	}
	specs := map[string]initialProviderACL{issuerPolicy: {paths}, wrapPolicy: {map[string]initialProviderACLRule{"auth/token/lookup-self": {[]string{"read"}}, mount + "/encrypt/" + key: {[]string{"update"}}}}, unwrapPolicy: {map[string]initialProviderACLRule{"auth/token/lookup-self": {[]string{"read"}}, mount + "/decrypt/" + key: {[]string{"update"}}}}}
	out := map[string]string{}
	for name, v := range specs {
		b, e := json.Marshal(v)
		if e != nil {
			return nil, ErrSetupUnavailable
		}
		out[name] = string(b)
	}
	return out, nil
}
