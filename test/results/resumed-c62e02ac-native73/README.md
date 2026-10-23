# native73 — worker claim refused at retention topology read

`excerpt/worker-admission/claim/claim/topology`: every fence re-read the
installer-pinned immutable topology ConfigMap (5 s lifetime, Kubernetes reads
under load). The reader now reuses a successful pinned read for 30 s.
