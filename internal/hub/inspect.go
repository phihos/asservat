package hub

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"asservat.local/asservat/internal/api"
)

// Inspection tells a user what they can choose before a capture, so that
// they need not know a process's path or the syntax of a packet filter:
// the programs that run in a workload's pods, and whom the pods talk to.

// inspect asks the node agents about the workload's pods and hands every
// reply to merge.
func (h *Hub) inspect(ctx context.Context, u User, cluster, namespace, workload string, q api.Query, merge func(api.Reply)) (api.Inspection, error) {
	in := api.Inspection{Pods: []string{}}
	if !api.ValidName(cluster) || !api.ValidName(namespace) {
		return in, errStatus{http.StatusBadRequest, "cluster and namespace are required"}
	}
	if err := h.allowed(ctx, u, cluster, namespace); err != nil {
		return in, err
	}
	res, err := h.agents.query(ctx, cluster, "", api.Query{Op: "resolve", Namespace: namespace, Workload: workload})
	if err != nil {
		return in, err
	}
	byNode := map[string][]string{}
	for _, p := range res.Pods {
		byNode[p.Node] = append(byNode[p.Node], p.Name)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var failed error
	q.Namespace = namespace
	for node, pods := range byNode {
		wg.Go(func() {
			q := q
			q.Pods = pods
			reply, err := h.agents.query(ctx, cluster, node, q)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == errNoAgent:
				in.NotInspected = append(in.NotInspected, pods...)
			case err != nil:
				failed = err
			default:
				for _, pod := range pods {
					if slices.Contains(reply.Skipped, pod) {
						in.NotInspected = append(in.NotInspected, pod)
					} else {
						in.Pods = append(in.Pods, pod)
					}
				}
				merge(reply)
			}
		})
	}
	wg.Wait()
	slices.Sort(in.Pods)
	slices.Sort(in.NotInspected)
	return in, failed
}

// Processes lists the programs that run in the workload's pods.
func (h *Hub) Processes(ctx context.Context, u User, cluster, namespace, workload string) (api.Inspection, error) {
	type key struct{ container, executable string }
	choices := map[key]*api.ProcessChoice{}
	pods := map[key]map[string]bool{}
	in, err := h.inspect(ctx, u, cluster, namespace, workload, api.Query{Op: "processes"}, func(r api.Reply) {
		for _, p := range r.Processes {
			k := key{p.Container, p.Executable}
			c := choices[k]
			if c == nil {
				c = &api.ProcessChoice{Container: p.Container, Executable: p.Executable, Name: p.Name}
				choices[k], pods[k] = c, map[string]bool{}
			}
			c.Processes++
			c.Main = c.Main || p.Main
			c.LargestResidentBytes = max(c.LargestResidentBytes, p.ResidentBytes)
			pods[k][p.Pod] = true
		}
	})
	in.Processes = []api.ProcessChoice{}
	for k, c := range choices {
		c.Pods = len(pods[k])
		in.Processes = append(in.Processes, *c)
	}
	// Per container: the main program first, then the largest.
	slices.SortFunc(in.Processes, func(a, b api.ProcessChoice) int {
		switch {
		case a.Container != b.Container:
			return strings.Compare(a.Container, b.Container)
		case a.Main != b.Main:
			if a.Main {
				return -1
			}
			return 1
		case a.LargestResidentBytes != b.LargestResidentBytes:
			return cmp.Compare(b.LargestResidentBytes, a.LargestResidentBytes)
		}
		return strings.Compare(a.Executable, b.Executable)
	})
	return in, err
}

// Traffic samples must fit one request: it stays open while the agents
// record, and proxies in front of the hub commonly end a request after a
// minute.
const maxSampleSeconds = 30

// Traffic records the packet headers of the workload's pods for some
// seconds and returns their connections, each with a packet filter for it.
func (h *Hub) Traffic(ctx context.Context, u User, cluster, namespace, workload string, seconds int) (api.Inspection, error) {
	if seconds == 0 {
		seconds = 5
	}
	if seconds < 1 || seconds > maxSampleSeconds {
		return api.Inspection{}, errStatus{http.StatusBadRequest, fmt.Sprintf("seconds must be between 1 and %d", maxSampleSeconds)}
	}
	type key struct {
		direction, protocol, peer string
		port                      int
	}
	flows := map[key]*api.Flow{}
	peers := map[key]map[string]bool{}
	in, err := h.inspect(ctx, u, cluster, namespace, workload, api.Query{Op: "traffic", Seconds: seconds}, func(r api.Reply) {
		for _, f := range r.Flows {
			k := key{f.Direction, f.Protocol, f.Peer, f.Port}
			sum := flows[k]
			if sum == nil {
				sum = &api.Flow{Direction: f.Direction, Protocol: f.Protocol, Port: f.Port, Peer: f.Peer}
				flows[k], peers[k] = sum, map[string]bool{}
			}
			sum.Packets += f.Packets
			sum.Bytes += f.Bytes
			sum.Pods++
			for _, p := range f.PeerList {
				peers[k][p] = true
			}
		}
	})
	if err != nil {
		return in, err
	}
	if err := h.Store.Audit(ctx, u.Name, "traffic.sample", "", map[string]any{"cluster": cluster, "namespace": namespace, "workload": workload, "seconds": seconds}); err != nil {
		return in, err
	}
	// Name the peers that the user may know: those of the namespace, or of
	// the cluster for an administrator.
	var ips []string
	for k := range flows {
		if k.peer != "" && !slices.Contains(ips, k.peer) {
			ips = append(ips, k.peer)
		}
	}
	names := map[string]string{}
	if len(ips) > 0 {
		reply, err := h.agents.query(ctx, cluster, "", api.Query{Op: "peers", Namespace: namespace, IPs: ips, All: u.Admin})
		if err != nil {
			return in, err
		}
		names = reply.Names
	}
	in.Seconds, in.Flows = seconds, []api.Flow{}
	for k, f := range flows {
		f.Peers, f.PeerName = len(peers[k]), names[f.Peer]
		f.Label, f.Filter = describeFlow(*f)
		in.Flows = append(in.Flows, *f)
	}
	slices.SortFunc(in.Flows, func(a, b api.Flow) int {
		if a.Bytes != b.Bytes {
			return cmp.Compare(b.Bytes, a.Bytes)
		}
		return strings.Compare(a.Label, b.Label)
	})
	return in, nil
}

// Profiles looks for the profile endpoints that the workload's pods serve:
// those of the catalog, on the ports that a pod listens on. One pod per node
// is asked, since the replicas of a workload serve the same.
func (h *Hub) Profiles(ctx context.Context, u User, cluster, namespace, workload string) (api.Inspection, error) {
	var found []api.ProfileTarget
	var ports []int
	in, err := h.inspect(ctx, u, cluster, namespace, workload, api.Query{Op: "profiles"}, func(r api.Reply) {
		for _, p := range r.Profiles {
			// The agent names the endpoint; what it is comes from the catalog.
			endpoint, known := api.FindProfileEndpoint(p.ID)
			if known && !slices.ContainsFunc(found, func(f api.ProfileTarget) bool { return f.Port == p.Port && f.ID == p.ID }) {
				found = append(found, api.ProfileTarget{Port: p.Port, ProfileEndpoint: endpoint})
			}
		}
		for _, port := range r.Ports {
			if !slices.Contains(ports, port) {
				ports = append(ports, port)
			}
		}
	})
	if err != nil {
		return in, err
	}
	if err := h.Store.Audit(ctx, u.Name, "profile.discover", "", map[string]any{"cluster": cluster, "namespace": namespace, "workload": workload}); err != nil {
		return in, err
	}
	slices.SortStableFunc(found, func(a, b api.ProfileTarget) int { return cmp.Compare(a.Port, b.Port) })
	slices.Sort(ports)
	in.Profiles, in.Ports = found, ports
	if in.Profiles == nil {
		in.Profiles = []api.ProfileTarget{}
	}
	return in, nil
}

// usualProtocols names what commonly runs on a port. It is a hint for the
// reader, not a finding: the sample holds headers only.
var usualProtocols = map[int]string{
	53: "DNS", 80: "HTTP", 443: "HTTPS", 2379: "etcd", 3306: "MySQL", 4317: "OTLP", 5432: "PostgreSQL", 5672: "AMQP",
	6379: "Redis", 6443: "Kubernetes API", 9092: "Kafka", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

// describeFlow returns a flow in words and the packet filter that selects
// it. The filter of incoming traffic names only the port, because its peers
// change; the filter of outgoing traffic names the peer too.
func describeFlow(f api.Flow) (label, filter string) {
	port := strings.ToUpper(f.Protocol) + " port " + strconv.Itoa(f.Port)
	if usual := usualProtocols[f.Port]; usual != "" {
		port += " (usually " + usual + ")"
	}
	filter = f.Protocol + " port " + strconv.Itoa(f.Port)
	switch f.Direction {
	case api.FlowIn:
		peers := "1 peer"
		if f.Peers != 1 {
			peers = strconv.Itoa(f.Peers) + " peers"
		}
		return "Incoming on " + port + " from " + peers, filter
	case api.FlowOut:
		peer := f.Peer
		if f.PeerName != "" {
			peer = f.PeerName + " (" + f.Peer + ")"
		}
		return "To " + peer + " on " + port, "host " + f.Peer + " and " + filter
	}
	return "Inside the pod on " + port, filter + " and (net 127.0.0.0/8 or host ::1)"
}

func (h *Hub) listProcesses(w http.ResponseWriter, r *http.Request, u User) error {
	in, err := h.Processes(r.Context(), u, r.PathValue("cluster"), r.PathValue("namespace"), r.URL.Query().Get("workload"))
	if err != nil {
		return err
	}
	return reply(w, in)
}

func (h *Hub) findProfiles(w http.ResponseWriter, r *http.Request, u User) error {
	in, err := h.Profiles(r.Context(), u, r.PathValue("cluster"), r.PathValue("namespace"), r.URL.Query().Get("workload"))
	if err != nil {
		return err
	}
	return reply(w, in)
}

func (h *Hub) sampleTraffic(w http.ResponseWriter, r *http.Request, u User) error {
	seconds := 0
	if v := r.URL.Query().Get("seconds"); v != "" {
		var err error
		if seconds, err = strconv.Atoi(v); err != nil || seconds < 1 {
			return errStatus{http.StatusBadRequest, "seconds must be a positive number"}
		}
	}
	in, err := h.Traffic(r.Context(), u, r.PathValue("cluster"), r.PathValue("namespace"), r.URL.Query().Get("workload"), seconds)
	if err != nil {
		return err
	}
	return reply(w, in)
}
