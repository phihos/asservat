package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"strconv"
)

func WorkerConfigurationAuditKey(c authorization.DownloadWorkerConfiguration) string {
	p := c.Profile
	return "download-worker-configuration/v1/" + p.InstallationID + "/" + p.ClusterID + "/" + p.Configuration.UID + "/" + strconv.FormatInt(p.Configuration.Generation, 10)
}
func (r Receipt) ValidWorkerConfiguration(c authorization.DownloadWorkerConfiguration) bool {
	return c.Valid() && r.Key == WorkerConfigurationAuditKey(c) && (r.Version != "null" && identity.Text(r.Version, 1024)) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 64<<10 && r.SHA256 != (artifact.Digest{})
}
