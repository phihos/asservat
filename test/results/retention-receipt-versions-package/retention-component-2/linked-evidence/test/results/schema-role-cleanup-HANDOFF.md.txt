# Native schema-incarnation fixture cleanup correction

One fixture-only path, manifest `a3a560629c0f937898b02df07939d387a0699f24cc977b5e3e1b51494864a581`, patch `2a5434712a3a76cca30a5a3c3c43f6fefeaebd11baa5993d334a102c45c024c2`. Current live base verified. No production behavior, grants, deadlines or cleanup assertion is relaxed.

Actual parent run schema-consumption-first82409 exited1 with1230 unchanged source hashes and owned-lab cleanup[]. Both changed-database/postmaster negatives passed and the original recovery-blocked claim was created. The Go test failed in final DROP ROLE cleanup for all three purpose roles. Archived PostgreSQL log explicitly lists retained schema/table/column privilege dependencies after administrative DROP OWNED returned. Do not count this run as native success.

The fixture now invokes existing InitialSQLRoles.Retire through the original manager grantor, after the purpose pool's defer closes it, then drops each inert named fixture role. Manager pool remains open until the outer defer. A single finite five-second cleanup context is unchanged. The existing production retirement verifies exact original grants/password state and removes only its compiled union; no broad CASCADE or permission bypass is introduced. Errors keep static phase plus sanitized five-character SQLSTATE only; raw provider messages, SQL and credentials remain absent.

Source-only staged/gofmt during parent native hold. Compilation and native rerun are PENDING. Parent may compile the isolated overlay, then run `^TestInitialSchemaWithRealPostgres$` in its owned custody fixture. Sources frozen; no active build or external lab.
