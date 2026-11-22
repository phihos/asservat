package hub

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/pprof/driver"
	"github.com/google/pprof/profile"
)

// A profile in pprof's format is shown by pprof itself: the hub parses the
// profile and holds the pages of pprof's web interface (flame graph, top,
// graph, peek) for the view. The browser shows them as they are.

// pprofPages are the pages of pprof's interface that a view serves. Left
// out are those that write pprof's settings file and those that read the
// profiled program's binary, which the hub does not have.
var pprofPages = []string{"/", "/flamegraph", "/top", "/graph", "/peek", "/download"}

// pprofStart serializes the starts of pprof, which parses its flags into
// package variables.
var pprofStart sync.Mutex

func (h *Hub) profilePages(ctx context.Context, a storedArtifact) (map[string]http.Handler, error) {
	var plain bytes.Buffer
	if err := h.plain(ctx, a, &plain); err != nil {
		return nil, fmt.Errorf("open artifact: %w", err)
	}
	parsed, err := profile.Parse(&plain)
	if err != nil {
		return nil, errStatus{http.StatusUnprocessableEntity, "pprof cannot read this profile: " + err.Error()}
	}
	pprofStart.Lock()
	defer pprofStart.Unlock()
	var all map[string]http.Handler
	err = driver.PProf(&driver.Options{
		// -http makes pprof build its web interface; HTTPServer takes the
		// pages instead of listening. The profile carries its symbols. The
		// source is a fixed word: Fetch hands over the parsed profile.
		Flagset: &pprofFlags{FlagSet: flag.NewFlagSet("pprof", flag.ContinueOnError), args: []string{"-http=localhost:0", "-no_browser", "-symbolize=none", "--", "profile"}},
		Fetch:   fetched{parsed},
		UI:      pprofUI{},
		HTTPServer: func(args *driver.HTTPServerArgs) error {
			all = args.Handlers
			return nil
		},
	})
	if err != nil {
		return nil, errStatus{http.StatusUnprocessableEntity, "pprof cannot show this profile: " + err.Error()}
	}
	pages := map[string]http.Handler{}
	for _, p := range pprofPages {
		pages[p] = all[p]
	}
	return pages, nil
}

// fetched hands pprof the profile that the hub already holds.
type fetched struct{ p *profile.Profile }

func (f fetched) Fetch(string, time.Duration, time.Duration) (*profile.Profile, string, error) {
	return f.p, "", nil
}

// pprofFlags gives pprof its command line.
type pprofFlags struct {
	*flag.FlagSet
	args []string
}

func (f *pprofFlags) StringList(name, def, usage string) *[]*string {
	return &[]*string{f.FlagSet.String(name, def, usage)}
}
func (f *pprofFlags) ExtraUsage() string   { return "" }
func (f *pprofFlags) AddExtraUsage(string) {}
func (f *pprofFlags) Parse(usage func()) []string {
	f.FlagSet.Usage = usage
	f.FlagSet.Parse(f.args)
	return f.FlagSet.Args()
}

// pprofUI is the terminal that pprof has not: it asks nothing and its
// messages are dropped, because the pages report their own errors.
type pprofUI struct{}

func (pprofUI) ReadLine(string) (string, error)     { return "", fmt.Errorf("no terminal") }
func (pprofUI) Print(...any)                        {}
func (pprofUI) PrintErr(...any)                     {}
func (pprofUI) IsTerminal() bool                    { return false }
func (pprofUI) WantBrowser() bool                   { return false }
func (pprofUI) SetAutoComplete(func(string) string) {}
