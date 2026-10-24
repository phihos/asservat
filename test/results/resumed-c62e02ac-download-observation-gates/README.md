# Policy observation candidate qualification

Frozen candidate: `768316a3bb10d53763661b1bbdd6b069a192ec84`.

- Full `make go-check`: actual exit **0**, 2924.562 seconds; 3765 tracked source hashes unchanged. Schema, vet and complete race/shard coverage ran.
- Specification, architecture, design and Go dependency gates: actual exit **0**, 10.891 seconds.
- `make permission-integration`: actual exit **0**, 174.040 seconds. Real Kubernetes/SQL/S3 observation, admission, reconciliation, local start and retention cases passed. Identity settings were reused within the original observation, then group removal and same-name replacement were detected after real original expiry. KMS and authority setup remain synthetic; this is not installed download qualification.
- All native source hashes match the frozen Git candidate. Harness cleanup reported no failure; independent Docker inspection confirms the owned node and two service containers are absent.

Exact commands, raw logs, source hashes and actual exits are retained in the corresponding directories. The installed investigation still requires its separate run.
