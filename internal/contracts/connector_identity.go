package contracts

type ConnectorDeployment struct {
	Namespace         string `json:"namespace"`
	ServiceAccount    string `json:"serviceAccount"`
	Deployment        string `json:"deployment"`
	ServingSlots      int    `json:"servingSlots"`
	RetainedProcesses int    `json:"retainedProcesses"`
}
