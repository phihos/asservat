# native68 — capacity admission window lapsed at query plan

`excerpt/plan`: SQL `query workload capacity unavailable`. Re-evaluated seconds
later every condition held; `capacity_managed_admission_until` requires the
context_storage_binding observation within 5 s, refreshed by hub-worker under
load. Relaxing to the authorized 30 s cadence.
