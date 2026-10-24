# native67 — projection-worker audit write refused by object store

`excerpt/worker-admission/audit/http-403`: the hub audit credential lacked the
`context-query-worker/v1/<root>/` and `acquisition-{enrollment,certificate}/v1/<purpose>/<installation>/`
prefixes added by 1d46304e. The installer owner recipe now grants them.
