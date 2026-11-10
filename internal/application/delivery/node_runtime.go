package delivery

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
)

func nextLiveRates(previous *collector.Report, current collector.Report) *collector.LiveActivityRates {
	if current.Live == nil {
		return nil
	}
	if previous == nil || previous.Live == nil {
		return nil
	}
	elapsed := current.ObservedAt.Sub(previous.ObservedAt)
	if elapsed <= 0 {
		return nil
	}
	before, after := previous.Live.Activity(), current.Live.Activity()
	delta := [8]int64{after.ScanEvents - before.ScanEvents, after.ScanBytes - before.ScanBytes, after.ScanCPUNanos - before.ScanCPUNanos, after.DeliveredRows - before.DeliveredRows, after.DeliveredBytes - before.DeliveredBytes, after.RefusedAdmissions - before.RefusedAdmissions, after.LostEvents - before.LostEvents, after.DroppedRows - before.DroppedRows}
	for _, value := range delta {
		if value < 0 {
			return nil
		}
	}
	seconds := elapsed.Seconds()
	return &collector.LiveActivityRates{ScanEventsPerSecond: float64(delta[0]) / seconds, ScanBytesPerSecond: float64(delta[1]) / seconds, ScanCPUNanosPerSecond: float64(delta[2]) / seconds, DeliveredRowsPerSecond: float64(delta[3]) / seconds, DeliveredBytesPerSecond: float64(delta[4]) / seconds, RefusedAdmissionsPerSecond: float64(delta[5]) / seconds, LostEventsPerSecond: float64(delta[6]) / seconds, DroppedRowsPerSecond: float64(delta[7]) / seconds}
}

// LiveRuntime aggregates current reports without node or workload labels. A
// missing/invalid predecessor makes all rates explicitly incomplete.
func (c *NodeChannel) LiveRuntime(cluster string) collector.LiveRuntimeSnapshot {
	if !authorization.UUID(cluster) {
		return collector.LiveRuntimeSnapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	out := collector.LiveRuntimeSnapshot{ClusterID: cluster, ObservedAt: now, FreshUntil: identity.Check(now, identity.Recheck).Until(), RatesComplete: true}
	for _, entry := range c.nodes {
		if entry.report == nil || entry.report.Live == nil || now.Sub(entry.reportedAt) > collector.StatusStaleAfter {
			continue
		}
		out.FreshUntil = identity.Earlier(out.FreshUntil, entry.reportedAt.Add(collector.StatusStaleAfter))
		out.Nodes++
		if out.Live == nil {
			out.Live = &collector.LiveActivity{}
		}
		activity := entry.report.Live.Activity()
		out.Live.Cohorts += activity.Cohorts
		out.Live.ScanEvents += activity.ScanEvents
		out.Live.ScanBytes += activity.ScanBytes
		out.Live.ScanCPUNanos += activity.ScanCPUNanos
		out.Live.DeliveredRows += activity.DeliveredRows
		out.Live.DeliveredBytes += activity.DeliveredBytes
		out.Live.RefusedAdmissions += activity.RefusedAdmissions
		out.Live.LostEvents += activity.LostEvents
		out.Live.DroppedRows += activity.DroppedRows
		out.Live.PendingRows += activity.PendingRows
		if entry.liveRates == nil {
			out.RatesUnavailable++
			continue
		}
		out.Rates.ScanEventsPerSecond += entry.liveRates.ScanEventsPerSecond
		out.Rates.ScanBytesPerSecond += entry.liveRates.ScanBytesPerSecond
		out.Rates.ScanCPUNanosPerSecond += entry.liveRates.ScanCPUNanosPerSecond
		out.Rates.DeliveredRowsPerSecond += entry.liveRates.DeliveredRowsPerSecond
		out.Rates.DeliveredBytesPerSecond += entry.liveRates.DeliveredBytesPerSecond
		out.Rates.RefusedAdmissionsPerSecond += entry.liveRates.RefusedAdmissionsPerSecond
		out.Rates.LostEventsPerSecond += entry.liveRates.LostEventsPerSecond
		out.Rates.DroppedRowsPerSecond += entry.liveRates.DroppedRowsPerSecond
	}
	out.RatesComplete = out.RatesUnavailable == 0
	if !out.RatesComplete {
		out.Rates = collector.LiveActivityRates{}
	}
	if !out.Valid(now) {
		return collector.LiveRuntimeSnapshot{}
	}
	return out
}
