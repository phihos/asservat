# Collector capability and submission

REQ-EXE-002 and S-02. Mechanisms follow
[ADR-330](../decisions/330-event-driven-system-design.md).

## Capability

The first profile needs to know, per cluster, whether collection is enabled
and which collector version, image and compiled projection digest are running.

- The enable flag is a Helm value of the connector release.
- The connector reports the actual collector version, image and projection
  digest when it connects and whenever they change, on its hub connection
  (D1/D2). The hub stores the report in SQL; it stays valid until replaced.
- Preview and admission compare the reported capability with the plan's
  required image and projection digest. A cluster without a matching report is
  `NotAvailable`.

Capability is a fact for planning, not a permission. The collector's own
identity is established by its projected ServiceAccount token and TLS (D3).

## Submission

`ContextSubmission` runs the public request in the caller's request context:

1. one authorization decision for the operation ([ADR-311](../decisions/311-operation-authority-recheck.md));
2. atomic admission with its audit row ([context admission](context-admission.md));
3. `StartContext` over the connector connection
   ([API execution class](api-context-execution.md)).

If the start fails after admission commits, the response returns the accepted
capture with the error. The dispatcher resumes accepted, unstarted captures from
SQL; the client does not need to resend anything. A retry with the same
idempotency key returns the stored capture and its current progress. A started
or stored capture is never started again. A new investigation needs a new
preview.

Public hub processes hold no collector SQL credentials, wrap keys or
acquisition access.
