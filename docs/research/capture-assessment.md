# Capture assessment: evidence and qualification

Checked 2026-10-09. The proposed assessment is deterministic planner/capability work, not an implemented performance predictor. It adds no runtime dependency or background evidence scan. Normative behavior is in [capture assessment](../../specs/capture-assessment.md).

Primary sources establish mechanism effects, not universal overhead numbers:

- [Go diagnostics](https://go.dev/doc/diagnostics) distinguishes heap allocation samples from object dumps, describes production profiling cost, recommends measuring that overhead, and notes interference between diagnostic mechanisms. This supports combination-aware warnings and rejecting a universal percentage prediction.
- [Go net/http/pprof](https://pkg.go.dev/net/http/pprof) documents bounded CPU/trace duration, the heap GC parameter and command-line output. The selected operation/options therefore matter to both impact and content; one generic “pprof is safe” label is insufficient.
- [GDB attaching](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Attach.html) documents that attachment stops the process and detachment resumes it. This supports an application-pause warning for that adapter, not a measured pause-time forecast.
- [GDB core generation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Core-File-Generation.html) describes memory selection and core generation. Size and completeness depend on the mechanism/configuration; maximum output bytes are not expected artifact size.

No Asservat pause, CPU, memory, latency, I/O or combined-workload measurement was made here. Exact runtime/engine/kernel/CNI/capture parameters, workload-rate envelopes and confidence/limitations must accompany qualified measurements. Enforced/configured budgets, modeled reservations and empirical predictions are distinct inputs. No causal attribution is established by a before/after production graph alone.

Privacy and deletion behavior reuse the reviewed [privacy specification](../../specs/privacy.md) and [earlier source research](privacy-retention.md). This work adds presentation and conservative mechanism classification, not a new legal interpretation or a GDPR-compliance claim. Direct retrieval of the EUR-Lex/Commission pages during this follow-up did not provide usable text, so no new legal claim relies on that retrieval. Automatic deletion remains limited to managed copies, with visible exceptions/failures and no recall of external disclosures.

Required validation extends EXP-17/18/19/21/22: matched/mismatched qualification records, stale/missing metrics, combined scope/accounting and conflicting profilers, metadata versus payload/argument modes, pprof versus full heaps, per-artifact retention arithmetic, deletion overrun, restricted/shared views, and user comprehension without repeated warning dialogs. **Runtime prediction accuracy and usability experiments remain NOT RUN.** Synthetic contract examples must label every numeric fixture as a configured limit or a synthetic estimate/measurement; they are not production evidence.
