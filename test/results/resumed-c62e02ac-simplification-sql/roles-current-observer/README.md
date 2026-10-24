# SQL role matrix with the current fixture observer

Frozen commit `114dd8996554ebda93de6d4a3740e340ed07243a`. The exact command and environment are in command.json. This reruns all five original selected role scenarios after the diagnostic failure established an expired synthetic fleet observation.

Actual harness exit 0, wall 131.646 seconds. Go package 46.527 seconds; selected top-level test 45.43 seconds. Matrix passed in 29.26 seconds; unknown-claim, lost-completion, held-lock and recovery-after-lock also passed. All required selections and their generated-role effect children are recorded in fleet.log and result.json.

Only the positive full-inventory fixture operations maintain the independent fleet observer; each observation retains five seconds, and the observer is stopped/joined before assertions. Production code and controlled negative/recovery paths are unchanged.

All 2750 harness inputs match the frozen commit and remained unchanged. cleanupFailures=[]; exact owned container IDs are absent and owned-label container/network lists are empty. Original command outputs are in owned-resource-checks.json.

Real PostgreSQL/TLS/SCRAM role creation and verification with S3/OpenBao activation are covered. Human and protected Kubernetes/root observations remain synthetic. This is not installed-workflow qualification or a benchmark.
