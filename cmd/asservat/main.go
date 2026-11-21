// Command asservat runs the hub or a node agent.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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
	dsnFile := f.String("dsn-file", "", "file with the PostgreSQL connection string")
	keyFile := f.String("master-key-file", "", "file with the 32-byte master key as 64 hex digits")
	dataDir := f.String("data-dir", "", "directory for encrypted evidence (instead of S3)")
	s3Endpoint := f.String("s3-endpoint", "", "S3 endpoint host[:port] for encrypted evidence")
	s3Bucket := f.String("s3-bucket", "", "S3 bucket")
	s3AccessKeyFile := f.String("s3-access-key-file", "", "file with the S3 access key")
	s3SecretKeyFile := f.String("s3-secret-key-file", "", "file with the S3 secret key")
	s3Insecure := f.Bool("s3-insecure", false, "use HTTP for the S3 endpoint")
	usersFile := f.String("users-file", "", "YAML list of static users: name, token, groups")
	adminGroups := f.String("admin-groups", "asservat-admins", "comma-separated groups whose members are administrators")
	retention := f.Duration("retention", 7*24*time.Hour, "how long evidence is kept")
	selfApproval := f.Bool("allow-self-approval", false, "let an administrator approve their own sensitive capture")
	localCluster := f.String("local-cluster", "", "register this cluster name with the token of local-token-file at startup")
	localTokenFile := f.String("local-token-file", "", "file with the join token of local-cluster")
	oidcIssuer := f.String("oidc-issuer", "", "OIDC issuer URL; accepts its ID tokens as bearer tokens")
	oidcClient := f.String("oidc-client-id", "", "expected audience of OIDC tokens")
	oidcUser := f.String("oidc-username-claim", "preferred_username", "claim with the user name, as the clusters' RBAC knows it")
	oidcGroups := f.String("oidc-groups-claim", "groups", "claim with the user's groups")
	oidcRedirect := f.String("oidc-redirect-url", "", "https://<hub-host>/auth/callback, registered at the issuer; enables the browser sign-in")
	oidcScopes := f.String("oidc-scopes", "openid,profile", "comma-separated scopes of the browser sign-in; the issuer must return the user name and groups claims for them")
	oidcSecretFile := f.String("oidc-client-secret-file", "", "file with the client secret, for a confidential client")
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
	c := hub.Config{MasterKey: key, AdminGroups: strings.Split(*adminGroups, ","), Retention: *retention, AllowSelfApproval: *selfApproval}
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
		if c.Blobs, err = hub.NewS3Blobs(*s3Endpoint, *s3Bucket, access, secretKey, !*s3Insecure); err != nil {
			return err
		}
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
	if *localCluster != "" {
		token, err := secret(*localTokenFile)
		if err != nil {
			return fmt.Errorf("local-token-file: %w", err)
		}
		sum := sha256.Sum256([]byte(token))
		if err := c.Store.AddCluster(ctx, *localCluster, sum[:]); err != nil {
			return err
		}
	}
	h, err := hub.New(c)
	if err != nil {
		return err
	}
	go h.RunRetention(ctx)
	server := &http.Server{Addr: *listen, Handler: h.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		server.Close()
	}()
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
	f.Parse(args)
	if *hubURL == "" || *node == "" {
		return errors.New("hub-url and node are required")
	}
	token, err := secret(*tokenFile)
	if err != nil {
		return fmt.Errorf("token-file: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
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
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	a := &agent.Agent{HubURL: strings.TrimRight(*hubURL, "/"), Token: token, Node: *node, Kube: kube, HTTP: &http.Client{Transport: transport}, Scratch: *scratch, Proc: "/proc"}
	a.Run(ctx)
	return nil
}
