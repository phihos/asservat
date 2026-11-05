# Current capacity audit-profile diagnostics

Signed `6297ff693c5d8bcc66137dbf00f31204459bcb5a` adds operator-only bounded
DETAIL to the demonstrated SQL23514 rejection. It changes no authority
predicate, SQLSTATE/message, success output, lifetime, read, role or runtime
state. Independent full-body comparison strips only DETAIL and matches the
effective migration65+74 body; Down restores it exactly, including the
30-second permission bound. The public adapter still returns generic
unavailability. The test-only native-download failure hook invokes existing
diagnostics after closing the response and before the unchanged failure.

Two separate pristine real-service campaigns passed:

| Command (prefix `python3 scripts/test-custody.py --fleet`) | Go duration | Passed tests | Harness/Go |
| --- | --- | --- | --- |
| `--run '^TestCapacityAuditProfileDiagnosticsWithRealPostgres$' --result-name capacity-audit-profile-diagnostics` | 35.743s | 5 | 0/0 |
| `--run '^TestCustodyUpgradeSchemaWithRealPostgres$' --result-name saved-packet-query-upgrade139-audit-detail` | 8.073s | 401 | 0/0 |

Both reports match all 4,197 Git source hashes, preserve unchanged inputs and
report no cleanup failures. Fresh controls bracket permission/source/trust
expiry negatives. The actual compiled reader rejects the same expired state
with the old and new bodies; DETAIL is 818/814/809 bytes and the public adapter
remains generic. Source expiry uses its actual 30-second interval while
independent fixture producers remain current. The upgrade compares actual
function definitions through 139→138→139, including exact restoration of the
audit reader. Initial authority/native administrator facts remain synthetic.

Focused ordinary/race, SQL generation and spec/architecture/import checks
passed in their named logs. Fourteen deterministic gzip originals and their
hashes are retained in the manifest. They qualify diagnostics and refusal
preservation, not the unknown installed failure's cause or an availability fix.
The next hosted attempt may either complete or retain the missing current
guard timing/category; no native-download success is asserted here.
