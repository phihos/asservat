// Command asservat runs the hub or a node agent.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/oauth2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	"asservat.local/asservat/internal/agent"
	"asservat.local/asservat/internal/hub"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: asservat hub|agent [flags]")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "hub":
		err = runHub(ctx, os.Args[2:])
	case "agent":
		err = runAgent(ctx, os.Args[2:])
	case "core-handler":
		err = handleCore(os.Args[2:])
	case "jvm-attach": // the agent, started again as a JVM's user
		err = agent.AttachJVM(os.Args[2:], os.Stdin, os.Stdout)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func secret(file string) (string, error) {
	b, err := os.ReadFile(file)
	return strings.TrimSpace(string(b)), err
}

func runHub(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("hub", flag.ExitOnError)
	listen := f.String("listen", ":8080", "address to serve HTTP on")
	metricsListen := f.String("metrics-listen", "", "address to serve the hub's own figures on for Prometheus, at /metrics and without sign-in; empty: not served")
	dsnFile := f.String("dsn-file", "", "file with the PostgreSQL connection string")
	keyFile := f.String("master-key-file", "", "file with the 32-byte master key as 64 hex digits")
	dataDir := f.String("data-dir", "", "directory for encrypted evidence (instead of S3)")
	debuginfod := f.String("debuginfod-urls", "", debuginfodHelp)
	workDir := f.String("work-dir", "", "directory for files that are open in a viewer, decrypted while they are open (default: the system's temporary directory)")
	sharkd := f.String("sharkd", "sharkd", "Wireshark's sharkd, which reads packet captures for their viewer")
	goTrace := f.String("go-trace", "gotrace", "Go's trace tool (cmd/trace), which shows Go execution traces for their viewer")
	s3Endpoint := f.String("s3-endpoint", "", "S3 endpoint host[:port] for encrypted evidence")
	s3Bucket := f.String("s3-bucket", "", "S3 bucket")
	s3AccessKeyFile := f.String("s3-access-key-file", "", "file with the S3 access key")
	s3SecretKeyFile := f.String("s3-secret-key-file", "", "file with the S3 secret key")
	s3Insecure := f.Bool("s3-insecure", false, "use HTTP for the S3 endpoint")
	usersFile := f.String("users-file", "", "YAML list of static users: name, token, groups")
	adminGroups := f.String("admin-groups", "asservat-admins", "comma-separated groups whose members are administrators")
	retention := f.Duration("retention", 7*24*time.Hour, "how long evidence is kept")
	selfApproval := f.Bool("allow-self-approval", false, "let an administrator approve their own sensitive capture")
	auditToLog := f.Bool("audit-to-log", false, "write every entry of the audit log to standard output as well, one line of JSON each")
	clustersFile := f.String("clusters-file", "", "YAML file with the clusters whose agents may join: a list of name and token")
	localCluster := f.String("local-cluster", "", "name of the hub's own cluster, whose agents join with the token of local-token-file")
	localTokenFile := f.String("local-token-file", "", "file with the join token of local-cluster")
	oidcIssuer := f.String("oidc-issuer", "", "OIDC issuer URL; accepts its ID tokens as bearer tokens")
	oidcClient := f.String("oidc-client-id", "", "expected audience of OIDC tokens")
	oidcUser := f.String("oidc-username-claim", "preferred_username", "claim with the user name, as the clusters' RBAC knows it")
	oidcGroups := f.String("oidc-groups-claim", "groups", "claim with the user's groups")
	oidcRedirect := f.String("oidc-redirect-url", "", "https://<hub-host>/auth/callback, registered at the issuer; enables the browser sign-in")
	oidcScopes := f.String("oidc-scopes", "openid,profile", "comma-separated scopes of the browser sign-in; the issuer must return the user name and groups claims for them")
	oidcSecretFile := f.String("oidc-client-secret-file", "", "file with the client secret, for a confidential client")
	alertTokenFile := f.String("alert-token-file", "", "file with the secret that Alertmanager presents at /api/alerts; without it the hub accepts no alerts")
	f.Parse(args)

	dsn, err := secret(*dsnFile)
	if err != nil {
		return fmt.Errorf("dsn-file: %w", err)
	}
	keyHex, err := secret(*keyFile)
	if err != nil {
		return fmt.Errorf("master-key-file: %w", err)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("master-key-file: %w", err)
	}
	c := hub.Config{MasterKey: key, AdminGroups: strings.Split(*adminGroups, ","), Retention: *retention, AllowSelfApproval: *selfApproval, WorkDir: *workDir, Sharkd: *sharkd, GoTrace: *goTrace, DebuginfodURLs: debuginfodServers(*debuginfod)}
	switch {
	case *dataDir != "":
		if err := os.MkdirAll(*dataDir, 0o700); err != nil {
			return err
		}
		c.Blobs = hub.DirBlobs(*dataDir)
	case *s3Endpoint != "":
		access, err := secret(*s3AccessKeyFile)
		if err != nil {
			return fmt.Errorf("s3-access-key-file: %w", err)
		}
		secretKey, err := secret(*s3SecretKeyFile)
		if err != nil {
			return fmt.Errorf("s3-secret-key-file: %w", err)
		}
		blobs, err := hub.NewS3Blobs(*s3Endpoint, *s3Bucket, access, secretKey, !*s3Insecure)
		if err != nil {
			return err
		}
		c.Blobs = blobs
		// Said at the start and not a reason to stop: the server may come
		// later, and credentials that may write need not be allowed to ask,
		// so the warning says what was asked and not what will happen.
		check, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := blobs.Check(check); err != nil {
			slog.Warn("the evidence store did not confirm its bucket: uploads fail if the bucket is not there or the server not reachable, and work if the credentials may only not ask", "endpoint", *s3Endpoint, "bucket", *s3Bucket, "error", err)
		}
		cancel()
	default:
		return errors.New("set data-dir or s3-endpoint")
	}
	if *usersFile != "" {
		b, err := os.ReadFile(*usersFile)
		if err != nil {
			return err
		}
		if err := yaml.Unmarshal(b, &c.Users); err != nil {
			return fmt.Errorf("users-file: %w", err)
		}
	}
	if *clustersFile != "" {
		b, err := os.ReadFile(*clustersFile)
		if err != nil {
			return err
		}
		if err := yaml.Unmarshal(b, &c.Clusters); err != nil {
			return fmt.Errorf("clusters-file: %w", err)
		}
	}
	if *alertTokenFile != "" {
		if c.AlertToken, err = secret(*alertTokenFile); err != nil {
			return fmt.Errorf("alert-token-file: %w", err)
		}
		// Anyone who presents it can make the watches for alerts record.
		if len(c.AlertToken) < 32 {
			return errors.New("alert-token-file: the alert token needs at least 32 characters")
		}
	}
	if *localCluster != "" {
		token, err := secret(*localTokenFile)
		if err != nil {
			return fmt.Errorf("local-token-file: %w", err)
		}
		c.Clusters = append(c.Clusters, hub.Cluster{Name: *localCluster, Token: token})
	}
	if *oidcIssuer != "" {
		var endpoint oauth2.Endpoint
		if c.Verify, endpoint, err = hub.OIDCVerifier(ctx, *oidcIssuer, *oidcClient, *oidcUser, *oidcGroups); err != nil {
			return fmt.Errorf("oidc-issuer: %w", err)
		}
		if *oidcRedirect != "" {
			c.OAuth = &oauth2.Config{ClientID: *oidcClient, Endpoint: endpoint, RedirectURL: *oidcRedirect, Scopes: strings.Split(*oidcScopes, ",")}
			if *oidcSecretFile != "" {
				if c.OAuth.ClientSecret, err = secret(*oidcSecretFile); err != nil {
					return fmt.Errorf("oidc-client-secret-file: %w", err)
				}
			}
		}
	}
	// The database may start at the same time as the hub.
	for attempt := 1; ; attempt++ {
		if c.Store, err = hub.OpenStore(ctx, dsn); err == nil {
			break
		}
		if attempt == 30 || ctx.Err() != nil {
			return fmt.Errorf("database: %w", err)
		}
		slog.Warn("database not reachable yet", "error", err)
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	defer c.Store.Close()
	if *auditToLog {
		c.Store.AuditTo(os.Stdout)
	}
	h, err := hub.New(c)
	if err != nil {
		return err
	}
	names := []string{}
	for _, cluster := range c.Clusters {
		names = append(names, cluster.Name)
	}
	if err := c.Store.KeepWatches(ctx, names); err != nil {
		return err
	}
	go h.RunRetention(ctx)
	go h.RunSchedule(ctx)
	server := &http.Server{Addr: *listen, Handler: h.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		server.Close()
	}()
	if *metricsListen != "" {
		// Bound before the hub serves: a port that is taken fails the start, not the scrapes.
		listener, err := net.Listen("tcp", *metricsListen)
		if err != nil {
			return fmt.Errorf("metrics-listen: %w", err)
		}
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", h.Metrics())
		metrics := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			<-ctx.Done()
			metrics.Close()
		}()
		go func() {
			if err := metrics.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
				slog.Error("metrics are not served", "address", *metricsListen, "error", err)
			}
		}()
	}
	slog.Info("hub listening", "address", *listen)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func runAgent(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("agent", flag.ExitOnError)
	hubURL := f.String("hub-url", "", "URL of the hub")
	tokenFile := f.String("token-file", "", "file with the cluster's join token")
	node := f.String("node", os.Getenv("NODE_NAME"), "name of this node")
	caFile := f.String("ca-file", "", "PEM file with the CA of the hub's certificate, if it is not publicly trusted")
	scratch := f.String("scratch", "/scratch", "directory for a core file until it is uploaded")
	debuginfod := f.String("debuginfod-urls", "", debuginfodHelp)
	coreSpool := f.String("core-spool", "", "directory at the same path on the node and in this container; set to make this agent the node's core handler, which keeps the cores of crashed processes in watched pods")
	corePattern := f.String("core-pattern-file", "/proc/1/root/proc/sys/kernel/core_pattern", "the node's kernel.core_pattern")
	f.Parse(args)
	if *hubURL == "" || *node == "" {
		return errors.New("hub-url and node are required")
	}
	token, err := secret(*tokenFile)
	if err != nil {
		return fmt.Errorf("token-file: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// From the agent's own source ports, which packet captures leave out.
	transport.DialContext = agent.DialHub
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("ca-file contains no certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	kube, err := kubeClient(config)
	if err != nil {
		return err
	}
	a := &agent.Agent{HubURL: strings.TrimRight(*hubURL, "/"), Token: token, Node: *node, Kube: kube, HTTP: &http.Client{Transport: transport}, Scratch: *scratch, Proc: "/proc"}
	// A pod's host name is its name, as the agent's pod has its own network.
	a.Pod, _ = os.Hostname()
	a.DebuginfodURLs = debuginfodServers(*debuginfod)
	if *coreSpool != "" {
		a.Cores = agent.CoreSpool(*coreSpool)
		restore, err := a.Cores.Install(*corePattern)
		if err != nil {
			return fmt.Errorf("core handler: %w", err)
		}
		defer restore()
		slog.Info("this agent is the node's core handler", "spool", *coreSpool)
	}
	a.Run(ctx)
	return nil
}

// handleCore is run by the kernel on the node, as "core-handler <pid>
// <time>" and the values for the node's previous handler, with a core on
// standard input. The spool is the directory of the
// binary. Nobody reads its output, so what it did with the last core goes
// to a file there.
func handleCore(args []string) error {
	self, err := os.Executable()
	if err != nil || len(args) < 2 {
		return errors.New("usage: core-handler <pid> <time> [what the node's previous handler takes], run by the kernel")
	}
	spool := filepath.Dir(self)
	outcome, err := agent.CoreSpool(spool).Handle("/proc", args[0], args[1], os.Stdin, args[2:]...)
	if err != nil {
		outcome = "failed: " + err.Error()
	}
	os.WriteFile(filepath.Join(spool, "last-core"), []byte(time.Now().Format(time.RFC3339)+" pid "+args[0]+": "+outcome+"\n"), 0o600)
	return err
}

const debuginfodHelp = "debuginfod servers, separated by spaces or commas, from which gdb fetches the debug information of stripped programs when a core is described; they are sent the build IDs of those programs and their libraries. While any is named, the debug packages of RHEL's universal base images, Rocky, Alma, Amazon Linux and Alpine are downloaded from these distributions' package servers too, and the helper library that reads the managed stacks of a .NET core from Microsoft's symbol server. Empty: none, and the stacks of stripped programs show addresses"

// debuginfodServers reads the list of servers as the debuginfod client takes it.
func debuginfodServers(list string) string {
	return strings.Join(strings.FieldsFunc(list, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }), " ")
}

// kubeClient returns the agent's client for the API server, without the
// limit of 5 requests a second that client-go sets by itself: a capture asks
// for every pod of the workload on the node at once, and behind that limit
// the recordings of 200 pods started 40 seconds late and their logs failed.
// What an agent may ask of the API server is for the server to say, which
// it does with API Priority and Fairness.
func kubeClient(config *rest.Config) (*kubernetes.Clientset, error) {
	config = rest.CopyConfig(config)
	config.QPS = -1
	return kubernetes.NewForConfig(config)
}
