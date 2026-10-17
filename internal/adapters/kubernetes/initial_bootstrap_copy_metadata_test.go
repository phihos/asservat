package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Use the actual producer object builder, including its installation/request
// provenance. A hand-written metadata fixture previously omitted both fields
// and therefore could not detect that cleanup rejected its own original copies.
func TestInitialBootstrapCopyProducerMetadataRemainsBoundDuringMarkRecovery(t *testing.T) {
	for _, index := range []int{1, 2} {
		for _, resumed := range []bool{false, true} {
			t.Run(strconv.Itoa(index)+"/marked-"+strconv.FormatBool(resumed), func(t *testing.T) {
				f := newBootstrapPassiveFixtureVersion(t, true, contracts.InitialBootstrapCopyClosureFormat)
				if _, err := f.producer.ReadPassiveHistory(context.Background()); err != nil {
					t.Fatal("original protected public observation", err)
				}
				_, m, passive := bootstrapCopyStateFixture(t)
				state, err := bootstrapReadCopyState(f.desired, m, passive)
				if err != nil {
					t.Fatal(err)
				}
				object, err := bootstrapPrivateObject(f.desired, f.state, index)
				if err != nil {
					t.Fatal(err)
				}
				secret := object.(*core.Secret)
				// PrepareProjection supplies these exact original CREATE fields.
				secret.Annotations["asservat.io/bootstrap-operation-id"] = f.state.Creates[index].OperationID
				secret.UID = types.UID(f.state.Creates[index].Receipt.UID)
				secret.ResourceVersion = f.state.Creates[index].Receipt.ResourceVersion
				for _, b := range secret.Data {
					clear(b)
				}
				original := &meta.PartialObjectMetadata{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: *secret.ObjectMeta.DeepCopy()}
				ref, markedKey, removedKey := state.Claim.SQL, bootstrapCopySQLMarkedAnnotation, bootstrapCopySQLAnnotation
				if index == 2 {
					ref, markedKey, removedKey = state.Claim.Provider, bootstrapCopyProviderMarkedAnnotation, bootstrapCopyProviderAnnotation
				}
				if string(original.UID) != ref.UID || original.Annotations[initialNamespaceInstallationAnnotation] != state.Claim.InstallationID || original.Annotations[initialNamespaceRequestAnnotation] != state.Claim.RequestID {
					t.Fatal("fixture does not bind original producer/claim")
				}
				if resumed {
					original.Annotations[bootstrapCopyObjectAnnotation] = state.Claim.OperationID
				}
				for _, kind := range []string{"original", "missing-installation", "wrong-installation", "missing-request", "wrong-request", "extra-annotation", "wrong-mark"} {
					t.Run(kind, func(t *testing.T) {
						copy := original.DeepCopy()
						switch kind {
						case "missing-installation":
							delete(copy.Annotations, initialNamespaceInstallationAnnotation)
						case "wrong-installation":
							copy.Annotations[initialNamespaceInstallationAnnotation] = ownerID(98)
						case "missing-request":
							delete(copy.Annotations, initialNamespaceRequestAnnotation)
						case "wrong-request":
							copy.Annotations[initialNamespaceRequestAnnotation] = ownerID(98)
						case "extra-annotation":
							copy.Annotations["unrelated.example/extra"] = "deny"
						case "wrong-mark":
							copy.Annotations[bootstrapCopyObjectAnnotation] = ownerID(98)
						}
						prior := f.extra
						writes, marks, broad := 0, 0, 0
						delete(f.metadata.Annotations, markedKey)
						f.extra = func(w http.ResponseWriter, r *http.Request) bool {
							if strings.HasSuffix(r.URL.Path, "/secrets/"+ref.Name) {
								if r.Header.Get("Accept") != bootstrapPartialMetadataAccept {
									broad++
								}
								if r.Method == http.MethodGet {
									permissionReply(w, copy)
									return true
								}
								if r.Method == http.MethodPatch {
									var ops []struct {
										Op, Path string
										Value    json.RawMessage
									}
									if json.NewDecoder(r.Body).Decode(&ops) != nil || len(ops) != 3 {
										t.Error("invalid exact copy mark")
										http.Error(w, "invalid", 400)
										return true
									}
									var uid, rv, operation string
									_ = json.Unmarshal(ops[0].Value, &uid)
									_ = json.Unmarshal(ops[1].Value, &rv)
									_ = json.Unmarshal(ops[2].Value, &operation)
									if uid != ref.UID || rv != copy.ResourceVersion || operation != state.Claim.OperationID || ops[2].Path != "/metadata/annotations/"+strings.ReplaceAll(bootstrapCopyObjectAnnotation, "/", "~1") {
										t.Error("mark changed original UID/RV/operation")
									}
									marks++
									copy.Annotations[bootstrapCopyObjectAnnotation] = operation
									copy.ResourceVersion = "2"
									permissionReply(w, copy)
									return true
								}
								t.Error("mark step attempted non-PATCH effect", r.Method)
								http.Error(w, "forbidden", 403)
								return true
							}
							if r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/secrets/"+f.metadata.Name) {
								var ops []struct{ Value json.RawMessage }
								if json.NewDecoder(r.Body).Decode(&ops) != nil || len(ops) != 3 {
									t.Error("invalid retained copy receipt")
									http.Error(w, "invalid", 400)
									return true
								}
								var value string
								_ = json.Unmarshal(ops[2].Value, &value)
								writes++
								f.metadata.Annotations[markedKey] = value
								f.metadata.ResourceVersion = strconv.Itoa(18 + writes)
								permissionReply(w, &f.metadata)
								return true
							}
							return prior(w, r)
						}
						defer func() { f.extra = prior }()
						err := f.producer.advanceCopyDelete(context.Background(), f.metadata.DeepCopy(), state, ref, nil, markedKey, removedKey)
						if kind == "original" {
							if err != nil || writes != 1 || !resumed && marks != 1 || resumed && marks != 0 {
								t.Fatal("original producer copy could not retain exact mark", err, "receipt writes", writes, "copy marks", marks)
							}
							r, err := contracts.DecodeInitialBootstrapCopyReceipt(strings.NewReader(f.metadata.Annotations[markedKey]))
							if err != nil || r.UID != ref.UID || r.ResourceVersion != copy.ResourceVersion {
								t.Fatal("recovery did not preserve original marked UID/RV")
							}
						} else if err == nil || writes != 0 || marks != 0 {
							t.Fatal("changed original copy reached closure effect", err, writes, marks)
						}
						if broad != 0 || f.seedFullReads != 0 || f.metadata.Annotations[removedKey] != "" {
							t.Fatal("metadata marking read private material or invented deletion")
						}
					})
				}
			})
		}
	}
}
