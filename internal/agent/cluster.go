package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"asservat.local/asservat/internal/api"
)

// answer serves a hub query from the cluster's Kubernetes API.
func (a *Agent) answer(ctx context.Context, q api.Query) api.Reply {
	var r api.Reply
	var err error
	switch q.Op {
	case "review":
		r.Allowed, err = a.review(ctx, q)
	case "workloads":
		r.Workloads, err = a.workloads(ctx, q.Namespace)
	case "resolve":
		r.Pods, err = a.resolve(ctx, q.Namespace, q.Workload)
	default:
		err = fmt.Errorf("unknown query %q", q.Op)
	}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

// review asks the cluster's RBAC whether the user may exec into pods of the
// namespace. That right already exposes a pod's memory, files and traffic.
func (a *Agent) review(ctx context.Context, q api.Query) (bool, error) {
	sar, err := a.Kube.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
		User: q.User, Groups: q.Groups,
		ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: q.Namespace, Verb: "create", Resource: "pods", Subresource: "exec"},
	}}, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return sar.Status.Allowed, nil
}

func (a *Agent) workloads(ctx context.Context, namespace string) ([]string, error) {
	out := []string{}
	deployments, err := a.Kube.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, d := range deployments.Items {
		out = append(out, "Deployment/"+d.Name)
	}
	statefulSets, err := a.Kube.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, s := range statefulSets.Items {
		out = append(out, "StatefulSet/"+s.Name)
	}
	daemonSets, err := a.Kube.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, d := range daemonSets.Items {
		out = append(out, "DaemonSet/"+d.Name)
	}
	pods, err := a.Kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, p := range pods.Items {
		if len(p.OwnerReferences) == 0 {
			out = append(out, "Pod/"+p.Name)
		}
	}
	slices.Sort(out)
	return out, nil
}

// resolve returns the running pods of a workload.
func (a *Agent) resolve(ctx context.Context, namespace, workload string) ([]api.Pod, error) {
	kind, name, _ := strings.Cut(workload, "/")
	var pods []corev1.Pod
	if kind == "Pod" {
		p, err := a.Kube.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		pods = []corev1.Pod{*p}
	} else {
		var selector *metav1.LabelSelector
		switch kind {
		case "Deployment":
			d, err := a.Kube.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			selector = d.Spec.Selector
		case "StatefulSet":
			s, err := a.Kube.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			selector = s.Spec.Selector
		case "DaemonSet":
			d, err := a.Kube.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			selector = d.Spec.Selector
		default:
			return nil, fmt.Errorf("unsupported workload kind %q", kind)
		}
		list, err := a.Kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(selector)})
		if err != nil {
			return nil, err
		}
		pods = list.Items
	}
	out := []api.Pod{}
	for _, p := range pods {
		if p.Status.Phase != corev1.PodRunning || p.Spec.NodeName == "" {
			continue
		}
		out = append(out, api.Pod{Name: p.Name, Node: p.Spec.NodeName})
	}
	return out, nil
}
