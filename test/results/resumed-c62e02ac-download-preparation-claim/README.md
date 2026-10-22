# Native55 worker preparation discriminator

Candidate `d47f9a3caf08b390793357d0dea9a31409d6d529` passed the exact selected real PostgreSQL/S3 subtest. The actual dispatcher obtains one authority observation, reserves the worker, writes and acknowledges its encrypted audit, and claims launch under the same original interval and compiled installed SQL grants. The test deliberately stops at the first Job-create port; SQL then confirms one audited/claimed worker with no Job or binding.

The first Job boundary was reached after **184.796 ms**, with **4.303 s** left on the retained authority. The selected subtest passed in 2.29 s; its parent test took 2.70 s; the race-enabled package took 3.771 s. The owned harness exited 0; the parent wrapper took 43.882 s. `sql/custody.log` preserves every measured phase and the intentional Job-boundary sentinel. Its initial authority trace prints a zero-value remaining duration before the original authority has been captured; the next line records the real returned timestamp, and all effect-stage lines use that bound.

```sh
python3 scripts/test-custody.py --run '^TestContextAdmissionWithRealServices$/^download-worker-installed-original-authority$'
```

The harness recorded 2,754 unchanged source hashes; the parent broader pre/post check recorded 3,778 sources with no changes. Both are separate scopes. Cleanup reported no failures, and independent read-back confirmed the two owned containers and network absent. See the unmodified reports under `sql/`. Compile-only also exited 0 (integration 0.015 s, no tests run), with both owned hashes unchanged. Exact compile environment/command and raw logs are under `compile/`. Tool terminal observations are in `verification.json`.

## Limits and next step

This uses the existing synthetic protected-source/human-identity fixture and real published evidence, SQL effect fences and encrypted S3 audit. The three involved pools have the installed one-connection and hot-session/cold-worker behavior; this is not whole-hub concurrency or provider credential-provisioning qualification. Session provisioning precedes the measured worker operation. Upstream public HTTP, runtime-readiness/plan/source/attachment deadline propagation, Kubernetes Job creation/enrollment and native transfer are excluded. The selected test passed on its first external run: it does **not** reproduce or establish the cause of native55. Native55 remains a failed installed journey with a durably audited worker and no claim; acknowledgement uncertainty and inherited earlier bounds remain possible.

No runtime behavior, limits, retry counts or deadlines changed for this test. Next, qualify the independently reproduced readiness/planning lifetime coupling before changing the runtime; full installed download and S-02 remain open.
