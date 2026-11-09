package postgres

// Reuse hub-runtime's existing credential/pool. This is a shared duty, not a
// separately mintable role; no live table or detailed scope read is granted.
func publicRuntimeLiveWatchGrants() []publicRuntimeGrant {
	return []publicRuntimeGrant{
		{"function", "live_watch_prune(uuid)", "", "EXECUTE"},
		{"function", "live_watch_configure(uuid,uuid,uuid,bytea,jsonb)", "", "EXECUTE"},
		{"function", "live_watch_create(uuid,uuid,bytea,jsonb,bytea,timestamptz)", "", "EXECUTE"},
		{"function", "live_watch_change(uuid,uuid,bytea,jsonb,bigint,bigint,timestamptz)", "", "EXECUTE"},
		{"function", "live_watch_current(uuid,uuid,bytea,jsonb,timestamptz)", "", "EXECUTE"},
		{"function", "live_watch_owner(uuid,bytea,uuid,bytea)", "", "EXECUTE"},
		{"function", "live_watch_read_control(uuid,bytea,uuid)", "", "EXECUTE"},
		{"function", "live_watch_close_control(uuid,bytea,uuid,bigint,uuid)", "", "EXECUTE"},
	}
}
