# Native content terminal closure correction

Nine paths frozen under work/manifest.json; live source untouched. No native wire, SQL migration, byte limit, identity interval or worker reconnect behavior changes.

The previous real SQL/S3 run delivered all 352 exact native bytes and marked SQL Completed, but its content worker returned Uncertain. The fixture only logged that result and therefore did not qualify a clean happy path. A deterministic real two-hop h2 regression now reproduces the cause: after HubOperation acknowledges the final sink, the caller closes its SQL owner; the relay's subsequent fresh SQL check rejects that legitimate retirement before forwarding the already emitted final Done. Remote EOF is not needed to reproduce the defect.

Only validated relay closure now consumes NativeFrameGate.TerminalLease: the gate's original complete checked identity/operation/certificate/sequence with its monotonically shortened original deadline. It performs no producer query, authorization refresh or renewal. Known cancellation, denial and expiry remain binding. The private serverStream.SendTerminal facet accepts only a zero-byte Done with the exact operation and valid nonce/closure phase; relay validation separately pins the exact expected nonce/phase. Ordinary Send, hub production of Done, metadata, data, commands, commit, worker closed input and final sink acknowledgement retain full current checks. Inbound bounded prefetch can use the snapshot, but cannot authorize a nonterminal forward. No general NativeStream capability was added.

The SQL fixture now waits for three distinct exact positive worker Joined outcomes (preparation, observation and content), propagates errors, and retains exact bytes/hash, key-slot and SQL completion checks. A byte/accounting success with an uncertain worker can no longer pass.

Actual checks (GOMAXPROCS=2, TMPDIR=/home/phil/.cache/asservat-build/tmp, -p 2, overlay.json):
- before.log: deterministic two-hop regression against original production code FAILS, exit 1: hub succeeds, connector returns download unavailable and worker cannot join. before-incomplete-test-source.log preserves the earlier helper type mismatch, not behavioral evidence.
- after-focused.log: focused snapshot and actual h2 positive/negative cases pass under race detection, exit 0. Includes self-retirement; known revocation/cancellation/shortening; wrong phase/reference; nonzero bytes and nonterminal substitution; zero/uninitialized gate; original deadline preservation.
- after-race.log: full affected native, evidence and mtls race suites pass, exit 0 (2.288s, 1.543s, 8.487s). Existing failed/partial final write, lost final acknowledgement, data post-check and cancellation/join regressions remain passing.
- compile.log: integration package compiles, exit 0; no external tests ran.
- vet.log: native/evidence/mtls/integration vet passes, exit 0.

Next: parent hash review/apply, then exact TestContextAdmissionWithRealServices/download-worker-native-exchange selected native run with frozen source and cleanup verification. The tightened fixture has not yet run against external services. This remains the bounded 4 KiB context flow, not long-lived/generic large-artifact qualification. Continue ADR122 native listener/installed read composition afterward; its staged native_exchange.go interface split must be rebased to preserve this new method.
