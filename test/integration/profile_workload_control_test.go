package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The fixture owner alone changes this synthetic application's profiler. These
// controls are not product operations, evidence or production authority.
type profileWorkloadState struct {
	OwnerRunning    bool  `json:"owner_running"`
	RuntimeBusy     bool  `json:"runtime_busy"`
	ProfileRequests int64 `json:"profile_requests"`
	AuthRequests    int64 `json:"auth_requests"`
	AuthDenied      int64 `json:"auth_denied"`
}

func profileWorkloadControl(ctx context.Context, k kubernetes.Interface, namespace, podName, podUID, command string) (profileWorkloadState, error) {
	var zero profileWorkloadState
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pod, err := k.CoreV1().Pods(namespace).Get(ctx, podName, meta.GetOptions{})
	if err != nil || podUID == "" || string(pod.UID) != podUID {
		return zero, errors.New("profile fixture original Pod unavailable")
	}
	proxy := func(method, suffix string) *rest.Request {
		return k.CoreV1().RESTClient().Verb(method).Namespace(namespace).Resource("pods").Name(podName+":8080").SubResource("proxy").Suffix("fixture", suffix)
	}
	if command != "state" {
		var request *rest.Request
		switch command {
		case "start", "stop":
			request = proxy("POST", "cpu-profiler/"+command)
		case "normal", "missing":
			request = proxy("POST", "profile-mode").Body([]byte(command))
		default:
			return zero, errors.New("unknown profile fixture command")
		}
		if err := request.Do(ctx).Error(); err != nil {
			return zero, err
		}
	}
	body, err := proxy("GET", "cpu-profiler").Stream(ctx)
	if err != nil {
		return zero, err
	}
	defer body.Close()
	b, err := io.ReadAll(io.LimitReader(body, 257))
	if err != nil || len(b) > 256 {
		return zero, errors.New("profile fixture state unavailable")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var out struct {
		OwnerRunning    *bool  `json:"owner_running"`
		RuntimeBusy     *bool  `json:"runtime_busy"`
		ProfileRequests *int64 `json:"profile_requests"`
		AuthRequests    *int64 `json:"auth_requests"`
		AuthDenied      *int64 `json:"auth_denied"`
	}
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.OwnerRunning == nil || out.RuntimeBusy == nil || out.ProfileRequests == nil || *out.ProfileRequests < 0 {
		return zero, errors.New("profile fixture state invalid")
	}
	var authRequests, authDenied int64
	if out.AuthRequests != nil {
		authRequests = *out.AuthRequests
	}
	if out.AuthDenied != nil {
		authDenied = *out.AuthDenied
	}
	if authRequests < 0 || authDenied < 0 {
		return zero, errors.New("profile fixture auth counters invalid")
	}
	return profileWorkloadState{AuthRequests: authRequests, AuthDenied: authDenied, OwnerRunning: *out.OwnerRunning, RuntimeBusy: *out.RuntimeBusy, ProfileRequests: *out.ProfileRequests}, nil
}
