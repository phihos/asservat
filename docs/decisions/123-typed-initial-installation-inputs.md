# ADR-123: Typed initial installation inputs and one-use handover

Status: accepted direction. Public-input production is implemented; native
qualification and the later private-input/handover composition remain pending.

The gated Pod and public credential interval from ADR-120 require actual final
startup inputs. These inputs must be produced from the retained original resource
identities, rather than passed as installation fixtures or reconstructed after a
restart with new UIDs.

The private preparer accepts a closed installation-owned public service document:
initial fleet settings, PostgreSQL, encrypted audit storage, key service, and the
same Kubernetes API endpoint. Its canonical public digest is retained before the
first effect. There are exactly nine additional typed public objects: witness,
fleet source, three compiled policy/binding pairs, and immutable startup inputs.
Existing Namespace/account/Pod receipts supply actual identities; independently
verified policy and binding receipts supply the final protection pins. The startup
digest therefore binds the original Pod UID and server-defaulted specification.

Each new effect requires the first acknowledged root CAS. Pending replay performs
only exact named lookup; it never retries an uncertain witness, admission resource
or startup input CREATE. A policy's original generation must be observed with clean
type checking before its receipt advances the sequence. The existing declarative
or gated-Pod retry exception does not expand to these operations. Missing unknown
results remain explicit required reconciliation work.

Handover must separately retain original staging and final pins, claim one staging
transition, independently verify final enforcement, and consume an original-UID
ungating claim. It must also verify the original private/provider readiness. None
of these later effects follows from an object receipt or public-input digest alone.
The current staged producer creates public inputs only; provider composition,
handover, activation reconciliation and positive retirement remain required.
