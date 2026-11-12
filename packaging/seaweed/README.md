# Bundled object-store image contract

The candidate is upstream SeaweedFS 4.53, multi-platform index
`sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0`.
The chart overrides the upstream root entrypoint with `/usr/bin/weed server`
as UID/GID 65532. Master, volume and filer listeners bind loopback; only the
TLS S3 port is exposed. Filer LevelDB, master metadata and volume data all use
the retained `/data` PVC. Telemetry, IAM HTTP, Iceberg, Lance and debug listeners
are disabled. This is one persistent instance, without HA or a backup claim.

Provider setup uses a complete retained private static identity configuration.
The provider administrator never enters ordinary Asservat credential projections.
The IAM Secret is mounted directly, without `subPath`. A bounded, named Pod exec
waits for the private expected configuration digest on stdin to match the mounted
file before signalling PID 1. It never prints configuration, credentials or the
digest. Actual scoped S3 probes must succeed before a phase is acknowledged.

The exact image still requires installed qualification of nonroot startup,
`/bin/sh`, `sha256sum`, `sleep`, `/bin/kill`, signal reload, TLS, IAM boundaries,
conditional writes, versions, multipart operations and cleanup. Source and chart
tests alone do not establish this qualification. Original credential state and
PVCs must be retained on uninstall/upgrade; loss requires recovery, not new keys.

Primary sources reviewed: upstream [4.53 release](https://github.com/seaweedfs/seaweedfs/releases/tag/4.53),
[server flags](https://github.com/seaweedfs/seaweedfs/blob/4.53/weed/command/server.go),
[static IAM reload](https://github.com/seaweedfs/seaweedfs/blob/4.53/weed/s3api/s3api_server.go),
and [admin gRPC authentication](https://github.com/seaweedfs/seaweedfs/blob/4.53/weed/s3api/s3api_server_grpc.go).
The latter includes a concrete correction relevant to
[GHSA-g96f-g546-47xf](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-g96f-g546-47xf);
this does not assert that all advisories are resolved.

The provider-only exec imports the existing pinned client-go v0.37.1 transport.
Its previously unused transitive modules are now recorded: Gorilla WebSocket
`v1.5.4-0.20250319132907-e064f32e3674` (BSD-2-Clause), Moby spdystream
`v0.5.1` (Apache-2.0) and Kubernetes streaming `v0.37.1` (Apache-2.0).
These match the official [client-go module pins](https://github.com/kubernetes/client-go/blob/v0.37.1/go.mod).
The [SPDY parser advisory](https://github.com/moby/spdystream/security/advisories/GHSA-pc3f-x583-g7j2)
identifies v0.5.1 as patched; the [Gorilla advisory list](https://github.com/gorilla/websocket/security/advisories)
identifies an older <=1.4.0 issue. The
[Kubernetes streaming project](https://github.com/kubernetes/streaming)
is the official staging transport shared with client-go. This review is not a
claim of comprehensive vulnerability clearance; normal dependency gates remain
required. No existing module version was upgraded for this import.

The finite preparation hook creates `<name>-objectstore-state` once, before the
provider StatefulSet/PVC. This immutable private Secret retains an independent
backend UUID, initialization UUID, exact public plan, administrator credential,
CA/key and one-year server certificate/key for `<name>-objectstore.<namespace>.svc`.
The chart mounts only `tls.crt`/`tls.key`. The separate mutable
`<name>-objectstore-iam` starts with the administrator alone and records its
original state Secret UID. A partial retry reconstructs that initial IAM from the
retained private material only while the exact StatefulSet, Pod and PVC remain
absent. Existing expanded IAM is validated and preserved, never reset. Missing
original state with any retained provider resource or IAM is recovery failure;
changed/expired material is refused, without automatic rotation or new keys.

The backend UUID is the administrator's private scope; it is not Asservat's
installation ID. Later grants use the actual installation ID minted by the
original bootstrap producer. Pending bucket ownership binds both independently,
as well as the original state Secret/PVC and initialization IDs.

Preparation uses at most 11 ordinary Kubernetes requests on first success, plus
one exact GET for each of at most two unknown CREATE replies. An established
state/IAM pair reopens with two GETs. No watch, runtime role, new storage pool or
background controller is added. The hook itself creates no bucket or provider
workload and grants no public collection/disclosure authority.
