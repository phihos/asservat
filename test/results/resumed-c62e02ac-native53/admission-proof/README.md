# Exact regional-join admission proof

All operations target retained native53 run `context-co1zv192`; no persistent write or cleanup was performed.

The original fixture's raw hub kubeconfig authenticates as `kubernetes-admin` (`identity.out`, SelfSubjectReview exit0). The retained public owner input pins only `system:serviceaccount:bootstrap-chain-10000000:install-bootstrap-runner` as its catalog administrator (`owner-selected.json`). The installed capability and private namespace policies retain that same administrator; the exact policies and bindings are archived here. The capability policy existed while its ConfigMap was absent, matching the first guarded-source create in `JoinRegionalCluster`.

`capability-create.json` reconstructs the exact immutable single-key ConfigMap settings from the retained public offer, regional join record and the candidate's fixed projection definition. `derivation.json` records source pointers and payload hash. It carries no secrets. The object namespace/name, selected installation/root/cluster/epoch, image and projection digests match the product builder's inputs.

Two identical server-side dry-run CREATE requests were made:

1. Original `kubernetes-admin` identity: actual exit1; the existing capability policy denied the request with `Asservat context capability administrator is required.` The API formatted this as Invalid, not the literal Forbidden label.
2. Exact pinned runner identity via administrator impersonation: actual exit0. The same object passed the installed admission controls.

`dry-run-commands.json` records full commands and actual exits. The capability ConfigMap was independently NotFound both before and after the two dry-run requests. Guards were neither modified nor disabled. This demonstrates the fixture's caller mismatch at the failed create boundary; it does not prove later join stages, request acquisition or download success.

`result-corrected.json` is the summary. Original `result.json` is retained to expose the initial text-classification error; all raw outputs and exits remain unchanged. Private kubeconfigs remained outside this directory and were removed after proof collection. The earlier permission reconciler start/begin changed log is not assigned as a cause: its existing supervisor intentionally retries after the preceding SQL controller lease.
