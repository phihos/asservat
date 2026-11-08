package bootstrap

import (
	"asservat.local/asservat/internal/domain/collector"
)

// cancel answers one cancelPacketCapture item (ADR-283). It only stops a
// running packet capture this process started for exactly the named work
// item; it starts nothing and its acceptance carries no result. The stopped
// capture still uploads its failure through its own original slot. A capture
// that already finished (or never started here) is accepted unchanged, so a
// repeated or late cancel is harmless.
func (n *nodePackets) cancel(w collector.Work) collector.Receipt {
	r := collector.Decide(w, n.now())
	if r.Reason == collector.ReasonWorkUnknown || r.Reason == collector.ReasonWorkExpired {
		return r
	}
	if w.Kind != collector.WorkCancelPacketCapture || w.CancelPacket == nil {
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	c := *w.CancelPacket
	n.budgetMu.Lock()
	running, ok := n.running[c.CaptureID]
	if ok && running.workID != c.WorkID {
		n.budgetMu.Unlock()
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	n.budgetMu.Unlock()
	if ok {
		running.cancel()
		running.live.Close()
	}
	r.Outcome, r.Reason = collector.OutcomeAccepted, ""
	return r
}
