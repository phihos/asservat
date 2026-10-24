# native58 (dd788576) — failed at installer continuation

Exit 1 after 815.8 s. Federation crash-looped ("protected configuration,
credentials or original deadline unavailable"). PostgreSQL shows
`connector-owner-read` (role pub_56) denied on `fleet_current_trust`: the
ADR-222 consolidation restricted `ownerIdentityRoleGrants` to `owner-runtime`,
so the federation registry purpose fell through to schema USAGE only.
Fixed by calling `ownerIdentityDutyGrants("registry")`; regression tests
`TestConnectorOwnerReadKeepsRegistryGrants` and
`TestEveryRuntimePurposeHasObjectGrants`. Fixture cleanup exit 0, clusters absent.
Capture/download not reached.
