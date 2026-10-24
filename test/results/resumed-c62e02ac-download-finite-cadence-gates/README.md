# Combined finite-download and response-cadence gates

Candidate: `17e0ff6387e5e472037bb3a0bfdd7239ddbec95b`.
Includes ADR-220 response-owned ordinary permission cadence, ADR-214 one initial
finite-prepare authority, and candidate-only namespace GET removal.

- Design command exits 0: spec-check, architecture-check, design-check and
  go-architecture-check. The first wrapper exits 1 because architecture-check
  regenerates validation.json from 1316 to 1321 positive checks. That exact
  generated change was reviewed and committed; the repeat exits 0 in 11.126 seconds
  with all 3791 non-result sources unchanged. Both receipts are retained.
- Real PostgreSQL/S3 command exits 0 in 67.863 seconds; Go exits 0 in 6.629 seconds
  (selected parent 5.56 seconds). Both download-worker-installed-original-authority
  and download-response-window-accounting pass, including the new nested
  response-permission-cadence-keeps-sql-revocation case (0.18 seconds). Current SQL
  suspension refuses work while the response retains its ordinary observation.
- All 2764 harness source hashes match the candidate and remain unchanged.
  Cleanup has no failures; independent container/network read-back confirms all
  fixture resources absent. The outer wrapper also records all 3791 non-result
  sources unchanged.

The compiled-role worker test stops deliberately at the first Job-create port;
it creates no Kubernetes Job. The response test uses actual SQL/S3 with synthetic
human/native authority inputs. These are not installed download bytes or sustained
provider qualification. Native57 is running separately on this same candidate;
no outcome is claimed here. The full current Go gate remains pending.

manifest.json records every archived file other than itself. Original failing
wrapper and passing command outcomes remain separate.
