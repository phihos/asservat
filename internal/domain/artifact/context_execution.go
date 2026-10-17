package artifact

// ContextExecutionClass distinguishes the source of a pod-status acquisition.
// The empty value preserves the historical node profile and its serialized
// identities. It never selects the API profile when node identity is missing.
type ContextExecutionClass string

const (
	ContextNodeExecution ContextExecutionClass = ""
	ContextAPIExecution  ContextExecutionClass = "kubernetesAPI"
)

func (c ContextExecutionClass) Valid() bool {
	return c == ContextNodeExecution || c == ContextAPIExecution
}

// ValidNodeIdentity rejects mixed profiles. Kubernetes API reads do not obtain
// node/boot authority or claim that their executor runs on the observed node.
func (c ContextExecutionClass) ValidNodeIdentity(node, boot string) bool {
	switch c {
	case ContextNodeExecution:
		return len(node) > 0 && len(node) <= 64 && uuid(boot)
	case ContextAPIExecution:
		return node == "" && boot == ""
	default:
		return false
	}
}
