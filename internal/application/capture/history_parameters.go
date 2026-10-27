package capture

import (
	"encoding/json"
	"encoding/json/jsontext"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

type HistoryKeys interface {
	AccountVersion() string
	HistoryDigest(string, []byte) (artifact.Digest, error)
}

// HistoryParameterKeys excludes the execution identity/digest and effective
// clamping from settings grouping. They remain in the authenticated snapshot.
func HistoryParameterKeys(k HistoryKeys, root string, p value.HistoryParameters) (selector, settings artifact.Digest, err error) {
	if k == nil || !authorization.UUID(root) || !p.Valid() || !p.Selector().Valid() {
		return selector, settings, value.ErrInvalid
	}
	s, err := json.Marshal(struct {
		Root     string
		Selector value.HistorySelector
	}{root, p.Selector()})
	if err != nil {
		return selector, settings, err
	}
	defer clear(s)
	c := jsontext.Value(s)
	if c.Canonicalize() != nil {
		return selector, settings, value.ErrInvalid
	}
	selector, err = k.HistoryDigest("selector", c)
	if err != nil {
		return selector, settings, err
	}
	// Only authored collection choices belong to settings equality. Original
	// effective clamping and execution digests are separately authenticated.
	b, err := json.Marshal(struct {
		Root                                  string
		Target                                any
		NamespaceUID, WorkloadUID, Diagnostic string
		Composition                           any
		Recipe, Dependencies                  json.RawMessage
		RequestedSeconds                      int64
	}{root, p.Target, p.NamespaceUID, p.WorkloadUID, p.Diagnostic, p.Composition, p.RecipeJSON, p.DependencyJSON, p.RequestedSeconds})
	if err != nil {
		return selector, settings, err
	}
	defer clear(b)
	c = jsontext.Value(b)
	if c.Canonicalize() != nil {
		return selector, settings, value.ErrInvalid
	}
	settings, err = k.HistoryDigest("settings", c)
	return selector, settings, err
}
