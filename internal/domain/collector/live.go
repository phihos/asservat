package collector

import "time"

// LiveRead is exact-source viewer work. It contains no collector program,
// capture request, ring/window selection or raw bytes. A node cannot turn it
// into arm/renew/Save work. Missing live support refuses the unknown purpose.
type LiveRead struct {
	Binding                                           SourceBinding
	Manual                                            *ManualLiveSource
	Inspect                                           bool
	ClusterID, NamespaceUID, WorkloadUID              string
	Projection                                        string
	PrivacyUntil                                      time.Time
	Generation                                        int64
	AfterSequence, AfterLost                          uint64
	AfterClockLost, AfterUnsupported, AfterSensorLost uint64
	Head                                              bool
	Limit                                             int
	WaitMS                                            int
	ReplyBytes                                        int
}

func (r LiveRead) Valid() bool {
	bound := r.Binding.Valid() && !r.Inspect
	if r.Manual != nil {
		bound = r.Binding == (SourceBinding{}) && r.Manual.Valid()
		if r.Inspect {
			bound = r.Binding == (SourceBinding{}) && r.Head && r.Manual.BindingValid() && r.Manual.StartedAt.IsZero() && r.Manual.HardUntil.IsZero()
		}
	}
	return bound && len(r.ClusterID) > 0 && len(r.ClusterID) <= 128 && len(r.NamespaceUID) > 0 && len(r.NamespaceUID) <= 128 && len(r.WorkloadUID) > 0 && len(r.WorkloadUID) <= 128 && (r.Projection == "packetMetadata" || r.Projection == "syscallMetadata" || r.Projection == "httpHeaders") && !r.PrivacyUntil.IsZero() && r.Generation >= 0 && r.Generation <= 1000000000 && r.AfterSequence <= 1<<53-1 && r.Limit >= 1 && r.Limit <= 100 && r.WaitMS >= 0 && r.WaitMS <= 5000 && (r.ReplyBytes == 0 || r.ReplyBytes >= 1024 && r.ReplyBytes <= 24<<10)
}
