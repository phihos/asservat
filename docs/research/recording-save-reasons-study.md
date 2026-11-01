# Recording Save reasons: preimplementation size and composition study

Study base: `5ca61018da96b832c3ca401c51365000e872a4bd`, isolated
`feature/s04-recording-save-reasons`. No production/schema changes, providers,
network fixtures, staging or commits. The two accompanying tests are local
serialization/crypto studies, not a reason implementation or qualification.

## Requirement and proposed boundary

`specs/recording-saves.md` (REQ-SAV-001/002) already accepts optional `reason`.
`specs/contracts/mcp-tools.json:11370` bounds it to 1–512 Unicode characters;
512 supplementary scalars occupy 2048 UTF-8 bytes. Preserve valid text verbatim;
absence remains allowed. This is descriptive user data, not collection authority,
consent, or an extra approval. `specs/execution.md:15` excludes reasons from
collection digests. `specs/capture-history.md:13,29,78` excludes them from repeat
settings and restoration. Do not add a reason to grants or source bindings.

Current runtime omits this canonical input in
`scripts/investigation-schemas.py:214` and
`internal/transport/presentation/recording_save_operations.go`. The proposed
slice would connect that input through `RecordingSavePreviewRequest`, the
immutable passive blueprint, mandatory encrypted capture audit and authorized
capture metadata. No collection or source pinning occurs at preview.

The existing reference scaffolding is agent architecture, not a maintainer
requirement: `domain/capture/preview.go:34,163` and
`application/capture/context_investigation.go` currently treat reason expiry and
its reader freshness as capture-authority bounds. Revise that coupling. Reason
unavailability/expiry may affect its display; it must not invalidate an already
accepted capture, shorten source/processing deadlines or require per-child
reason revalidation. An unsupported reason at first preview must be explicit,
never silently discarded.

## Actual existing crypto authority

The preview-serving hub already owns **audit/control-metadata**, not raw evidence,
wrap and unwrap ports:

- `internal/bootstrap/owner_deployment.go:155–178,665–680` obtains installed owner
  provider effects and constructs `publicAuditStore` with their Sealer/Opener.
- `internal/bootstrap/public_context_compose.go:168–178,337` holds those ports and
  already supplies them to `HistoryCodec`. Regional history dispatch stores
  encrypted bytes; it does not supply the hub's history decryption key.
- `internal/adapters/kms/owner_provider_effects.go:57–67` fixes audit encrypt/decrypt
  paths; its transport rejects other host/path/method combinations.
- `internal/adapters/providerconfig/owner_provider_recipe.go:74–94` grants separate
  audit-wrap/audit-unwrap tokens only exact configured Transit encrypt/decrypt
  `update`, plus bounded self lookup/renew/revoke. Existing provider lifetime
  guards preserve source/recovery/current token deadlines and concurrency.
- Browser credentials use separate SessionTransit wiring (`public_identity.go`);
  artifact wrapping is separately scoped (`owner_provider_artifact.go`). Neither
  is proposed for reuse. No raw artifact unwrap grant is added.

Thus zero new provider keys/credentials/ACL paths is feasible, but a new reason
format and authenticated associated data still require implementation and actual
provider qualification. Existing ports alone do not qualify their new use.

## Measured size proof and counterexamples

Commands (actual exit 0 for each; TMPDIR on cache filesystem):

```
TMPDIR=/home/phil/.cache/asservat-build go test ./internal/application/capture -run '^TestRecordingSaveReasonSizeStudy$' -count=1 -v
TMPDIR=/home/phil/.cache/asservat-build go test ./internal/application/audit -run '^TestRecordingReasonOuterAuditFrameSizeStudy$' -count=1 -v
```

Logs are `/home/phil/.cache/asservat-build/recording-save-reasons-study-1.log`
and `recording-save-reasons-frame-study-1.log`. The later combined run is
`recording-save-reasons-combined-study-1.log` (both packages exit0;
capture0.007s/audit0.002s).

The first test uses the existing Tink AES256GCM/keyset algorithm from
`kms/browser.go`, a **distinct proposed reason format**, and the local base64
key-wrapper pattern from `objectstore/context_produce_test.go`. The wrapper is
not encryption/provider evidence. Payload round-trip and wrong-AD refusal use
real local AEAD. The AD sample is 280 bytes and binds version/root/capture plus
requester and scope digests; provider binding cap is 2048 bytes.

| Actual measured candidate | Bytes | Existing cap / result |
|---|---:|---|
| 512 supplementary Unicode scalars | 2048 | canonical512 scalars |
| Tink keyset / fake wrapped key / payload ciphertext | 108 / 144 / 2081 | local fake only |
| Envelope JSON, including maximum256-byte key reference | 3277 | not a provider maximum |
| Maximum-width normal-field CaptureIntent | 4685 | 8192 |
| Same intent + immutable reason reference | 4923 | fits8192 |
| Same + nested envelope | 8210 | **exceeds8192** |
| Valid escape-heavy CaptureIntent | 7501 | 8192 |
| Same + immutable reason reference | 7739 | fits8192 |
| Same + nested envelope | 11026 | **exceeds8192** |
| Maximum-width16-source preview + ref + same envelope | 61885 (61886 combined run) | fits131072 |
| Same preview, generic maximum wrapped ciphertext | 78126 | fits131072 |
| Capture candidate with generic maximum wrapped ciphertext | 27028 | **exceeds8192** |
| Actual audit-encoder escape-heavy OperationIntent baseline | 14654 | 16384 |
| Outer audit plaintext + full reason + small reference candidate | 16967 | **exceeds16384** |

These are reproducible valid counterexamples, not an exhaustive maximum proof.
Tink random key IDs can slightly change keyset encoding, and the resulting
ciphertext digest JSON can vary reference length (combined run +1 byte). The existing generic
`SealedKey` permits ciphertext16384/reference256 (`artifact/storage.go:97`),
and Transit permits wrapped ciphertext16384 (`kms/transit.go:192`). Never infer
universal fit from the short fake or narrow that existing key cap to fit reasons.
The second test calls the actual `captureEncoding` serializer (HTML escaping
already disabled), adding prototype fields only. No accepted DTO has changed.

**Result:** reference-only capture and grouped preview placement fit the studied
bounds. Inline nested-envelope capture placement fails. Clear reason inside the
already-encrypted intent object also has a valid16KiB counterexample. Do not
increase8/16/24/128KiB limits or claim this design ready for production.

## Smallest implementation direction and unresolved placement

Keep one immutable nullable `ReasonRef` column on real `context_capture` in SQL110;
for a group every child must have the same parent-bound ref. It contains only
ID/ciphertext digest/metadata retention binding, never plaintext, a keyset or the
wrapped body. Bind it in reconstruction and current SQL audit matching. Existing
`operation_audit.intent` may retain only encrypted reason material if needed for
recovery; this is existing control storage, not a new table or object. Its
representation cannot simply be copied wholesale into the8KiB capture payload.

Place the full reason in one of the **existing two mandatory encrypted audit
objects**, using the existing outer audit key rather than a second wrapped key
inside CaptureIntent. The measured intent counterexample rules out a naive
extra field there. The smallest remaining candidate is a body-bearing existing
24KiB **outcome** frame, with the intent carrying only the exact reference.
Before choosing it, measure the maximum full outcome (including its duplicated
intent/lifecycle), and specify independent acknowledgement/replay decoding:
verify exact parent/requester/scope/ref, decrypt or authenticate the retained
preview envelope, and bind its body to the mandatory object completion without
putting a plaintext-reason hash in SQL. This is a protocol change, not a field-only
change. An expired/cleaned preview cannot be its sole recoverable ciphertext
source after admission. Durable encrypted material must survive in the existing
pending operation journal until joined audit completion/its original retirement.
Do not add a new cleanup service, object, key or reason-authority lease.

If the24KiB candidate also fails, stop that additional mechanism for a concrete
format/layout review. Smaller alternatives are compacting repeated private audit
provenance without changing authority, or recording a current feature gap. No
new object/limit/credential is authorized by this study.

Idempotency remains `ContextRequestDigest(previewID)`
(`application/capture/context_preview_validation.go:25`). Exact ciphertext/ref
belongs to immutable protected blueprint bytes; the same preview/key never
reencrypts or replaces the reason. Accepted replay returns the original ref even
when preview authority expired. Collection/save scope, grant scope and repeat
blueprints remain reason-free. Authorized get_capture may display it once only
after all real group children pass current rights; no first-child authority alias.

## Complexity gate (11 answers)

| # | Answer |
|---|---|
| 1 | Explicit optional feature, currently unavailable; no measured production failure frequency. Size failures above are study-induced valid inputs. |
| 2 | Optional text and512-scalar bound are accepted. Agent expiry-as-authority restriction is not required and should be removed. |
| 3 | Helps users explaining saves; zero overhead for absent reason. Not required to acquire or inspect evidence. |
| 4 | Reuse Asservat's existing encrypted audit/control metadata precedent. No external-project comparison or provider performance claim was made; no novel service proposed. |
| 5 | 0 new keys, credentials, ACL paths, network destinations, collector privileges or browser tokens. New typed control purpose requires explicit review. |
| 6 | Existing unavailable/integrity-error paths; add no degraded fallback or silent omission. A new body/ref mismatch maps to existing refusal. |
| 7 | 0 new configuration knobs, timers or background tasks. |
| 8 | Existing Transit/Tink/object-store/SQL behavior only; actual provider max/latency remains unqualified. |
| 9 | Target1 wrap/reason preview,0 unwrap/admission if opaque binding suffices,1 unwrap/authorized display;0 extra Kube requests/watches; O(2048) text plus bounded envelope, one per preview. ExistingN group audit records may duplicate text. Actual16-source+wrap total5s must be measured later. |
| 10 | One nullable immutable SQL110 reference with legacyNULL behavior; populated downgrade refusal must follow existing pattern. No production migration implemented/tested. |
| 11 | Ref+existing mandatory audit object is preferable to a new reason object/service. Exact placement does not yet pass all unchanged caps; pause production and resolve that measured gap first. |

Next review decision: choose whether to pursue the24KiB outcome-body candidate
with exact maximum-frame proof and independent verification design. The current
study authorizes no production change and claims no provider/performance result.
