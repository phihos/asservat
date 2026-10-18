# Federation owner account read

Native installed journey 45 at `73316a3618a88635350c7169959936efdbc1e746`
refused `open/owner-first` after roughly 3.3 seconds. The closed diagnostic
covers the delegated RPC, its full owner authentication and the regional TLS
completion; it does not identify the first internal failure. The separate
capacity owner-registration success proves that SQL-only read can work, not
that the complete owner route/protection bracket succeeds.

Source inspection found a definite missing permission: `OwnerEndpoints`
independently GETs the owner ServiceAccount, while the rendered federation Role
only allowed core Pod/Service GETs. Its installation account receives no other
product binding supplying that read. The SQL-only registration path does not
need it. Existing discovery native tests used separate fixture RBAC that already
included the owner-account read; the installed workload test checked forbidden
writes but omitted this required read.

The correction passes the pinned inventory's owner-account name separately into
`BuildFederationWorkload`, rejects empty/invalid names and adds exact-name GET
only. It retains every native identity/protection read and the original bounds.
It does not grant LIST, token creation, account mutation or credential reads.

The new required-read regression failed on the original renderer, then both
focused renderer tests passed after the correction. The native selection
`^TestFederationOwnerReadsWithRealKubernetes$` is prepared but not yet run.
It uses actual controller-created objects, real scoped account tokens, the
exact rendered Role/ClusterRole and bindings, concrete `OwnerEndpoints`,
`OwnerRoutes`, `OwnerAuthenticator` and the native workload-protection adapter.
An owned-fixture administrator removes the required read, observes actual 403,
and restores the reviewed rendered rules before a new independently bounded
call. It also requires unrelated-account reads/listing, owner token creation and
credential listing to stay forbidden.

SQL registration/configuration acceptance and certificate presentation in this
fixture are explicitly synthetic. It exercises the hub's presented-certificate
side of delegated authentication, not actual regional TLS completion, federation
RPC, `ContextStartClient.Open`, the installed journey or evidence deletion.
A native passing result must retain exact source hashes and cleanup evidence;
this source defect alone does not establish native45's first observed cause.
