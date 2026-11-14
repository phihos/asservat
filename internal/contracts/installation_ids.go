package contracts

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"
)

// InstallationIDsRoot is where every hub component mounts the `<name>-ids`
// Secret generated once by `asservat secrets`, one file per key.
const InstallationIDsRoot = "/run/asservat/ids"

// InstallationIDs are the generated S values of the shared contract. `setup`
// seeds the trust and root rows with the same values.
type InstallationIDs struct {
	InstallationID   string
	ClusterID        string
	IssuerEpoch      string
	PermissionRootID string
	BrowserRootID    string
	SessionEpoch     string
	RoleSetupID      string
	PeerID           string
}

var ErrInstallationIDs = errors.New("installation IDs unavailable")

// InstallationIDError names the missing or invalid key of the IDs Secret.
type InstallationIDError string

func (e InstallationIDError) Error() string { return "installation ID " + string(e) + " unavailable" }
func (e InstallationIDError) Unwrap() error { return ErrInstallationIDs }

// ReadInstallationIDs reads every key of the IDs Secret from root. Each value
// is one canonical lowercase UUID; surrounding whitespace is ignored. All
// components use this one reader.
func ReadInstallationIDs(root *os.Root) (InstallationIDs, error) {
	var out InstallationIDs
	if root == nil {
		return out, ErrInstallationIDs
	}
	targets := map[string]*string{"installationID": &out.InstallationID, "clusterID": &out.ClusterID, "issuerEpoch": &out.IssuerEpoch,
		"permissionRootID": &out.PermissionRootID, "browserRootID": &out.BrowserRootID, "sessionEpoch": &out.SessionEpoch, "roleSetupID": &out.RoleSetupID, "peerID": &out.PeerID}
	for _, key := range InstallationIDKeys() {
		v, err := readInstallationID(root, key)
		if err != nil {
			return InstallationIDs{}, InstallationIDError(key)
		}
		*targets[key] = v
	}
	return out, nil
}

func readInstallationID(root *os.Root, key string) (string, error) {
	f, err := root.Open(key)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil || len(b) > 128 {
		return "", ErrInstallationIDs
	}
	v := strings.TrimSpace(string(b))
	parsed, err := uuid.Parse(v)
	if err != nil || parsed.String() != v {
		return "", ErrInstallationIDs
	}
	return v, nil
}
