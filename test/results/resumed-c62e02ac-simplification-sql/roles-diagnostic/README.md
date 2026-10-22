# Diagnostic matrix on abb48c73

Frozen commit `abb48c736b4934207ef1801fd724b8f82d33fc83`; exact command/environment in command.json. Only TestInitialInstallationWithRealServices/public-runtime-roles-matrix was selected.

Actual harness exit 1, wall 44.241 seconds. Go package 6.426 seconds; matrix 6.26 seconds. Before its final whole-inventory verify failure, Provision took 5376 milliseconds and completed all 81 original claims and 81 receipts. The fixture's original observed_at was 20:08:06.548786Z and fresh_until 20:08:11.548786Z. The immediate failure-only read returned database_now 20:08:11.931891Z, expired=true, suspended=false and recovery_blocked=false. Provider logs contain no timeout/cancellation/deadlock/connection-limit error. This establishes an expired fixture fleet observation as a sufficient failure condition; the closed original verify error does not identify its precise internal substep.

All 2750 harness source inputs matched the commit before/after, report source hashes match, sourceUnchangedDuringTest=true. cleanupFailures=[]; all three exact owned containers are absent and owned-label container/network listings are empty. Fresh raw checks are in owned-resource-checks.json. No reader fixture, retry or production edit was performed after this result.

The next candidate may model the existing continuously observed production source using a joined fixture observer only around positive full-inventory operations; deliberately held recovery/lock negative cases must remain unchanged. No deadline increase is required or qualified here.
