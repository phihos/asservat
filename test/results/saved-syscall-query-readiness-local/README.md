# Repeat readiness scheduling correction: local evidence

The product change reduces the response scheduling reserve from1s to750ms.
It retains original request/source deadlines, one joined hint/demand, independent
protected consumption and the1s binding freshness margin. The extra250ms can
permit one additional existing storage poll; no API/configuration/role/state is added.

The stable original-reserve boundary fails in4.009s. Its final test differs from
the retained RED snapshot only in comment spacing. With750ms, the same publication
at oldcutoff+125ms passes; original source expiry and selection change still refuse.
Final capture package races pass25.794s inside a combined command whose later
presentation compilation failed. That command is recorded as exit1, never a full pass.

After correcting only the timing fixture's historical assessment dates and a test
import alias, final presentation races pass7.622s. The existing audit/schema/response
path emits3,570B with3.130ms tail work and743.154ms remaining in the original5s.
This uses injected preview completion and in-memory audit, not external-provider or
installed successful-tail evidence. All initial failures and compile-only scope are
retained. Root `make pre-push` exits0, including552 console tests; self-test negative
cleanup messages in its log are expected fixture outputs.

The manifest preserves exact final affected inputs, patch, owner report, RED inputs,
original logs and required local-gate output. Independent review is recorded alongside
these originals. Actual installed Repeat and Stop still require fresh qualification.
