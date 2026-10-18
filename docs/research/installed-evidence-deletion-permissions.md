# Installed evidence deletion fixture permissions

The [installed continuation run 39122326430](https://github.com/phihos/asservat/actions/runs/39122326430)
at `9ef1103f83fd8377d007de89cedbb4aef5855c6d` failed before the public journey:
the fixture's `evidence-delete` credential received `AccessDenied` while
aborting an administrator-created synthetic multipart upload. That run is not
installed deletion evidence.

## Pinned backend explanation

The fixture pins
`chrislusf/seaweedfs@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d`.
The cached image's ID matches that digest; its OCI labels identify version
`4.48` and revision `530be3e37337488ecc34d58441e0bc476e121c93`.
The following observations come from that exact source revision:

- The [multipart action set](https://github.com/seaweedfs/seaweedfs/blob/530be3e37337488ecc34d58441e0bc476e121c93/weed/s3api/policy_engine/types.go#L41-L50)
  includes `AbortMultipartUpload`. The
  [statement matcher](https://github.com/seaweedfs/seaweedfs/blob/530be3e37337488ecc34d58441e0bc476e121c93/weed/s3api/policy_engine/engine.go#L165-L179)
  treats those actions as matching `PutObject`, including in Deny statements.
  An explicit matching Deny takes precedence over the exact abort Allow.
  This explains the previous policy's refusal; granting coarse `Write` would
  neither remove that Deny nor preserve the intended credential boundary.
- The [abort handler](https://github.com/seaweedfs/seaweedfs/blob/530be3e37337488ecc34d58441e0bc476e121c93/weed/s3api/s3api_object_handlers_multipart.go#L198-L225)
  and [underlying abort implementation](https://github.com/seaweedfs/seaweedfs/blob/530be3e37337488ecc34d58441e0bc476e121c93/weed/s3api/filer_multipart.go#L1135-L1158)
  do not compare the requesting principal with the multipart initiator.
- The [condition extraction](https://github.com/seaweedfs/seaweedfs/blob/530be3e37337488ecc34d58441e0bc476e121c93/weed/s3api/policy_engine/engine.go#L462-L471)
  derives `s3:RequestMethod` directly from `http.Request.Method`. Custom headers
  populate only `s3:x-amz-*` keys and cannot replace this value.

The fixture therefore keeps unconditional `GetObject`/`GetObjectVersion` denial
and conditions its `PutObject` denial on `StringNotEquals s3:RequestMethod DELETE`.
PUT and POST writes remain explicitly denied. The separate object-scoped Allows
permit only deletion, version deletion and multipart abort under `v1/`.
The credential retains only coarse `List:<evidence bucket>`; bucket policy
restricts all three inventories to `v1/`. This is a pinned SeaweedFS fixture
policy, not a portable production S3 policy or a change to runtime authority.

## Focused native qualification

Run the same permission helper used by the full installer against the existing
owned PostgreSQL/S3 custody harness, without Kubernetes:

```sh
python3 scripts/test-custody.py --run '^TestInstalledEvidenceDeleteCredentialWithRealServices$'
```

Only that exact selection provisions the fixed synthetic administrator and
separate List-only cleaner. It cannot combine with other fixture profiles.
The harness requires the exact top-level test to pass, freezes source hashes and
records owned-container cleanup in
`test/results/installed-evidence-delete-environment.json`.

The helper requires actual `AccessDenied` for current/version reads, PUT,
multipart creation, part upload, part copy, completion, foreign-prefix
inventory/deletion and bucket policy/versioning writes. The multipart write
probes use an administrator-created upload with an actual valid part, and the
copy source exists. These negative results establish refusal of the operations;
they do not identify which overlapping policy check generated each wire error.
The cleaner must then abort that administrator's upload and remove a version and
delete marker. Independent administrator inventories must confirm their absence.
Only the initial read-only credential subscription probe retries; none of these
permission assertions or mutation probes does. Synthetic cleanup is bounded.

The [focused native test](../../test/results/installed-evidence-delete-native-1/installed-evidence-delete.log)
passed on `2a5aea59a19a131c30a9c2df44a937a72903dd6c` on 2026-10-18.
Its [environment report](../../test/results/installed-evidence-delete-native-1/installed-evidence-delete-environment.json)
records the exact required test, exit 0, unchanged sources and no cleanup failures.
All 2,594 recorded source hashes match that commit's archive. The report SHA-256
is `37b4565243f897f9f7e3ccb4f87f40db2a1e8977f3d441480b6018c425a654b8`.
This qualifies these backend permissions only. Installed cleanup leases, expiry, signed audit
acknowledgement, refunds and preservation during a deletion outage still require
the full installed journey.
