# Single-runner Helm lifecycle qualification

The actual `make helm-integration` command exits 0 in 50.352 seconds on `c6be50caf35c904bccd2e44c5d773652dd9752a9`. All 22 captured source hashes match that commit and remain unchanged during the test.

The three foundation modes pass packaged installation, schema upgrade, rollback, invalid upgrade rejection and uninstall retention. Native server-side Helm lookup rejects pending, running, unknown, node-lost and deleting legacy continuation Pods without mutation; terminal succeeded/failed Pods permit rendering without adoption or deletion.

The fixture reports no cleanup failures. Independent read-back finds no remaining owned Helm clusters or containers.

These checks exercise chart lifecycle and native lookup. They do not execute the five-command installer or establish provider effects, public collection or an installed investigation. Those remain separate qualification.
