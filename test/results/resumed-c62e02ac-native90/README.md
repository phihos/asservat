# native90 — approved inspection passed again; query worker deleted at Job deadline, not retired

The query worker ran to activeDeadlineSeconds; Kubernetes deleted its Pod
(DeadlineExceeded) and SQL kept it charged (no termination). Test wait failed on
Pod not found.
