# native91 — native download prepared; content GET 503 at the first window

prepare_artifact_download reached Ready (worker enrolled, credentials
established). The content GET returned 503 (66-byte problem) with no hub log.
SQL: download_response a73a0e10 started 22:01:13.919, closed, window_count 0;
no download_window row; no PostgreSQL error. Control allocation
audit_write_until 2026-10-24 21:56:07 (protected capacity, ~24 h) exceeded
DownloadWindow.Valid's 8 h + 5 min cap, so BeginWindow returned ErrInvalid.
