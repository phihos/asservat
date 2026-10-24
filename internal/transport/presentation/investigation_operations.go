package presentation

import (
	"context"
	"encoding/json"
	"sort"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
)

// Operations contains only explicitly composed public application services.
// Implementations retain original metadata deadlines in every reply. A catalog
// or contract entry alone never creates a callable service.
type Operations interface {
	PublicOrigin() string
	ToolNames() []string
	Tool(string) (contracts.InvestigationTool, bool)
	Call(context.Context, identities.CurrentIdentity, string, json.RawMessage) (OperationReply, error)
}

// InvestigationOperations snapshots the configured public operation set. Only composed services are advertised; contracts alone never enable operations.
type InvestigationOperations struct {
	origin     string
	names      []string
	routes     map[string]Operations
	captures   *ContextOperations
	projection *ContextProjectionOperations
}

// NewInvestigationProjectionOperations adds only the two audited approved-read
// operations to an already composed installation. The returned routing snapshot
// has no unaudited projection Call path.
func NewInvestigationProjectionOperations(base *InvestigationOperations, projection *ContextProjectionOperations) (*InvestigationOperations, error) {
	if base == nil || projection == nil || projection.excerpts == nil || projection.results == nil || projection.contracts == nil || base.projection != nil {
		return nil, ErrOperationsConfiguration
	}
	out := *base
	out.names = append([]string(nil), base.names...)
	for _, name := range []string{"get_file_excerpt", "get_query_result"} {
		if _, exists := base.Tool(name); exists {
			return nil, ErrOperationsConfiguration
		}
		if _, exists := projection.contracts.Tool(name); !exists {
			return nil, ErrOperationsConfiguration
		}
		out.names = append(out.names, name)
	}
	out.projection = projection
	sort.Strings(out.names)
	return &out, nil
}

func NewInvestigationOperations(captures *ContextOperations, cases *ContextCaseOperations, downloads ...*ContextDownloadOperations) (*InvestigationOperations, error) {
	if len(downloads) > 1 || captures == nil && cases == nil && (len(downloads) == 0 || downloads[0] == nil) {
		return nil, ErrOperationsConfiguration
	}
	out := &InvestigationOperations{routes: map[string]Operations{}, captures: captures}
	var parts []Operations
	if captures != nil {
		parts = append(parts, captures)
	}
	if cases != nil {
		parts = append(parts, cases)
	}
	if len(downloads) == 1 && downloads[0] != nil {
		parts = append(parts, downloads[0])
	}
	for _, part := range parts {
		if out.origin == "" {
			out.origin = part.PublicOrigin()
		}
		if part.PublicOrigin() != out.origin {
			return nil, ErrOperationsConfiguration
		}
		for _, name := range part.ToolNames() {
			if _, duplicate := out.routes[name]; duplicate {
				return nil, ErrOperationsConfiguration
			}
			tool, ok := part.Tool(name)
			if !ok || tool.Name != name {
				return nil, ErrOperationsConfiguration
			}
			out.routes[name] = part
			out.names = append(out.names, name)
		}
	}
	sort.Strings(out.names)
	return out, nil
}
func (s *InvestigationOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.origin
}
func (s *InvestigationOperations) ToolNames() []string { return append([]string(nil), s.names...) }
func (s *InvestigationOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil {
		return contracts.InvestigationTool{}, false
	}
	if s.projection != nil && queryOperation(name) {
		return s.projection.contracts.Tool(name)
	}
	part, ok := s.routes[name]
	if !ok {
		return contracts.InvestigationTool{}, false
	}
	return part.Tool(name)
}
func (s *InvestigationOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	part := s.routes[name]
	// Preserve the existing browser's explicit CollectionDisabled response.
	// This exception does not advertise the mutation or exist in a case-only set.
	if name == "request_capture" && s.captures != nil {
		part = s.captures
	}
	if part == nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	return part.Call(ctx, current, name, raw)
}

// OperationCall contains a server-created correlation ID. Its private field is
// deliberately not a public wire input or a human-supplied context value.
type OperationCall struct {
	requestID       string
	queryInvocation *contextQueryInvocation
}

func (s *InvestigationOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	if s.projection != nil && queryOperation(name) {
		return s.projection.CallWithContext(ctx, current, call, name, raw)
	}
	part := s.routes[name]
	if name == "request_capture" && s.captures != nil {
		part = s.captures
	}
	switch p := part.(type) {
	case *ContextOperations:
		return p.CallWithContext(ctx, current, call, name, raw)
	case *ContextCaseOperations:
		return p.CallWithContext(ctx, current, call, name, raw)
	case *ContextDownloadOperations:
		return p.CallWithContext(ctx, current, call, name, raw)
	default:
		return OperationReply{}, contracts.ErrInvestigationWire
	}
}

// BrowserOperationSupported preserves only the existing disabled-capture
// explanation. MCP discovery remains exactly ToolNames. Case-only composition
// does not create capture routes by knowing their contract names.
func BrowserOperationSupported(operations Operations, name string) bool {
	if operations == nil {
		return false
	}
	if _, ok := operations.Tool(name); ok {
		return true
	}
	if name != "request_capture" {
		return false
	}
	switch s := operations.(type) {
	case *AuditedOperations:
		return s != nil && BrowserOperationSupported(s.inner, name)
	case *ContextOperations:
		return s != nil
	case *InvestigationOperations:
		return s != nil && s.captures != nil
	default:
		return false
	}
}
