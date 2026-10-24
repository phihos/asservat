# native62 — approved-only download denial still HTTP 503

The 3a08c480 fix sat behind AuditedOperations, which rejects a missing
evidence:download scope before dispatch and returned identity.ErrDenied
(transport 503). Fixed in the audit wrapper: a read-scoped session lacking
download scope gets the audited NotAvailable envelope. Capture and publication passed.
