package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func DownloadWorkerAuditKey(i authorization.DownloadWorkerIntent) string {
	return "download-worker-audit/v1/" + i.Authority.Scope.RootID + "/" + i.SessionID + "/" + i.ID + "/intent"
}
func (r Receipt) ValidDownloadWorker(i authorization.DownloadWorkerIntent) bool {
	return i.Valid() && r.Key == DownloadWorkerAuditKey(i) && (r.Version != "null" && identity.Text(r.Version, 1024)) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 128<<10 && r.SHA256 != (artifact.Digest{})
}
