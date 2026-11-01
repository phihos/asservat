package planning

import (
	"encoding/json"
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
)

// ProfileDescription is the listed and read view of one profile version
// (REQ-CPR-001). It grants nothing: previews still run every check.
type ProfileDescription struct {
	Ref                      value.ProfileRef
	DisplayName, Description string
	ExecutionModes           []string
	Available, Deprecated    bool
	Digest                   artifact.Digest
	// Definition is the published definition as read; content is untrusted.
	Definition json.RawMessage
}

// DescribeProfiles lists the embedded builtins, then the given catalog
// versions, restricted to catalog when it is not empty. A published document
// the compiler cannot decode is not listed.
// ponytail: an undecodable version is omitted rather than listed as broken;
// add a broken-entry row when publishers need that feedback in the UI.
func DescribeProfiles(catalog string, published []value.CatalogProfile) []ProfileDescription {
	var out []ProfileDescription
	if catalog == "" || catalog == "builtin" {
		for _, name := range builtinNames {
			if p, err := loadBuiltin(name); err == nil {
				out = append(out, describe(p, true))
			}
		}
	}
	for _, c := range published {
		if catalog != "" && c.Ref.Catalog != catalog {
			continue
		}
		p, err := parseProfileDocument(c.Document)
		if err != nil || p.Name != c.Ref.Name || p.Version != c.Ref.Version {
			continue
		}
		p.Ref, p.Deprecated = c.Ref, c.Deprecated
		out = append(out, describe(p, c.Enabled))
	}
	return out
}

func describe(p resolvedProfile, available bool) ProfileDescription {
	modes := map[string]bool{}
	for _, f := range p.Definition.EditableFields {
		if f.Field == "actionExecutionMode" {
			modes["ongoing"], modes["onTrigger"] = true, true
		}
	}
	for _, a := range p.Definition.Recipe.Actions {
		mode := a.ExecutionMode
		if mode == "" {
			mode = "ongoing" // action.schema.json x-execution-modes default
		}
		modes[mode] = true
	}
	var list []string
	for _, m := range []string{"onTrigger", "ongoing"} {
		if modes[m] {
			list = append(list, m)
		}
	}
	description := p.Definition.Description
	if description == "" {
		description = p.Definition.DisplayName
	}
	return ProfileDescription{Ref: p.Ref, DisplayName: p.Definition.DisplayName, Description: description, ExecutionModes: slices.Clip(list),
		Available: available, Deprecated: p.Deprecated, Digest: p.Digest, Definition: p.RawDefinition}
}
