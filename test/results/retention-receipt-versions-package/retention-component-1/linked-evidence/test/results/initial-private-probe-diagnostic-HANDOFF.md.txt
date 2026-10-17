# Frozen private probe diagnostic checkpoint

Three paths, no live changes. This diagnoses the first real Kubernetes failure; it does not fix or qualify the still-unknown native cause.

Production errors add static phase labels only and retain wrapped domain causes. An initial review failure now retains the review helper's underlying cause rather than collapsing it to unavailable; this does not change any allow/retry decision. The fixture keeps only 24 static HTTP route classes/status/error flags, request/review counts, and original root/anchor/claim/response presence booleans after failure. No HTTP body, URL, credential, Secret payload, payload digest or scope ID is logged. The observing administrator uses the same supplied authentication through the traced client. Current guards, deadlines, and one-use issuance are unchanged.

Qualification: `TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2 go test -race -p 2 -overlay=.../overlay.json ./internal/adapters/kubernetes ./test/integration -run '^TestInitialPrivate' -count=1` exited 0. Kubernetes 18.932s; integration package 1.053s, no tests selected there (compile only). Full log qualification-final.log. New test checks static labels, errors.Is cause, no token or scope identifier, and one issuance. No native fixture run by this agent.

Next: parent runs exact `^TestInitialPreparationPrivateProbeWithRealKubernetes$`, records static phase/status/state presence, then a separate correction may be required. This package is immutable.
