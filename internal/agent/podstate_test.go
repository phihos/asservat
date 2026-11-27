package agent

import (
	"bytes"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The pod and its events are stored as kubectl prints them: without the
// record of which manager set which field, which is most of an event and
// tells a reader nothing about the pod.
func TestPodStateIsStoredWithoutManagedFields(t *testing.T) {
	managed := []metav1.ManagedFieldsEntry{{Manager: "kubelet", Operation: metav1.ManagedFieldsOperationUpdate}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "shop", ManagedFields: managed}}
	events := []corev1.Event{{ObjectMeta: metav1.ObjectMeta{Name: "web-1.1", ManagedFields: managed}, Reason: "BackOff"}}
	files := podState(pod, events)
	for _, name := range []string{"pod.json", "events.json"} {
		if len(files[name]) == 0 {
			t.Fatalf("%s is missing", name)
		}
		if bytes.Contains(files[name], []byte("managedFields")) {
			t.Errorf("%s holds managedFields:\n%s", name, files[name])
		}
	}
	if !bytes.Contains(files["events.json"], []byte("BackOff")) || !bytes.Contains(files["pod.json"], []byte(`"web-1"`)) {
		t.Errorf("the pod or its event is not in the files: %s %s", files["pod.json"], files["events.json"])
	}
	if pod.ManagedFields == nil || events[0].ManagedFields == nil {
		t.Error("the objects that were handed in were changed")
	}
}
