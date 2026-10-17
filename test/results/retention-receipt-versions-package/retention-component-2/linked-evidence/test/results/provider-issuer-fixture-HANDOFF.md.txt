# Fixture-only provider compatibility regression

Frozen two-path package, with no production correction. Parent should apply this before the separate child-role cap fix, run the exact test, archive terminal source hashes/cleanup, then apply the fix and repeat.

The fixture establishes the actual role-only zero lookup field independently, then invokes production Issue/Verify/Revoke with separate synthetic bounded claims. It prints only finite scalar facts. A fixture root creates and finally revokes the finite issuer tree; it is not product authority or an installer journal. Each production Issue must perform exactly one POST. Successful results retain original deadlines; verification and revocation replay cannot create credentials.

The normal --fleet default regex now includes InitialProviderIssuer; explicit --run precedence and all cleanup/source hash behavior are unchanged.

Actual check: TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2 go test -p 2 -overlay ../fixture-overlay.json ./test/integration -run '^$': exit0 (compile only; external test not yet run). Provider unit failing-before is separately preserved in ../role-cap-before.log. No external fixture has been run by this agent.

Parent native command: python /home/phil/.cache/asservat-build/planning/run-qualified-native.py fleet initial-provider-issuer-before --run '^TestInitialProviderIssuerWithRealOpenBao$'. Expected current-code failure is product rejection after role-only provider lookup proves explicit_max_ttl=0. Unexpected earlier/later provider behavior requires its own diagnosis.
