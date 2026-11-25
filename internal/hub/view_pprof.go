package hub

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
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

// parsedProfile decrypts a profile into memory and parses it. A .NET trace
// and a JVM's flight recording become a profile of their samples.
func (h *Hub) parsedProfile(ctx context.Context, a storedArtifact) (*profile.Profile, error) {
	var plain bytes.Buffer
	if err := h.plain(ctx, a, &plain); err != nil {
		return nil, fmt.Errorf("open artifact: %w", err)
	}
	if strings.HasSuffix(a.Name, ".nettrace") {
		converted, err := nettraceProfile(plain.Bytes())
		if err != nil {
			return nil, errStatus{http.StatusUnprocessableEntity, "this .NET trace cannot be shown: " + err.Error()}
		}
		return converted, nil
	}
	if strings.HasSuffix(a.Name, ".jfr") {
		converted, err := flightRecordingProfile(plain.Bytes())
		if err != nil {
			return nil, errStatus{http.StatusUnprocessableEntity, "this flight recording cannot be shown: " + err.Error()}
		}
		return converted, nil
	}
	parsed, err := profile.Parse(&plain)
	if err != nil {
		return nil, errStatus{http.StatusUnprocessableEntity, "pprof cannot read this profile: " + err.Error()}
	}
	return parsed, nil
}

// profilePages returns pprof's pages for a profile; with a base, for the
// difference of the profile to it (pprof's -diff_base).
func (h *Hub) profilePages(ctx context.Context, a storedArtifact, base *storedArtifact) (map[string]http.Handler, error) {
	sources := fetched{}
	var err error
	if sources["profile"], err = h.parsedProfile(ctx, a); err != nil {
		return nil, err
	}
	// All functions, sorted by their own weight: what pprof begins with.
	args := append([]string{"-http=localhost:0", "-no_browser"}, pprofOptions(sources["profile"], "", false, -1)...)
	if base != nil {
		if sources["base"], err = h.parsedProfile(ctx, *base); err != nil {
			return nil, err
		}
		args = append(args, "-diff_base=base")
	}
	pprofStart.Lock()
	defer pprofStart.Unlock()
	var all map[string]http.Handler
	err = driver.PProf(&driver.Options{
		// -http makes pprof build its web interface; HTTPServer takes the
		// pages instead of listening. The profile carries its symbols. The
		// sources are fixed words: Fetch hands over the parsed profiles.
		Flagset: &pprofFlags{FlagSet: flag.NewFlagSet("pprof", flag.ContinueOnError), args: append(args, "--", "profile")},
		Fetch:   sources,
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

// profileText returns a profile as pprof's text report of the functions
// with the most weight ("top"), for readers that cannot open the viewer:
// of the profile's kind of value named by sampleType, or else of its last
// one, as pprof chooses; sorted by a function's own weight, or with
// cumulative by its weight with everything it calls.
func (h *Hub) profileText(ctx context.Context, a storedArtifact, sampleType string, cumulative bool) (string, error) {
	parsed, err := h.parsedProfile(ctx, a)
	if err != nil {
		return "", err
	}
	var kinds []string
	for _, kind := range parsed.SampleType {
		kinds = append(kinds, kind.Type)
	}
	if sampleType != "" && !slices.Contains(kinds, sampleType) {
		return "", errStatus{http.StatusBadRequest, fmt.Sprintf("the profile has no values of kind %q; it has: %s", sampleType, strings.Join(kinds, ", "))}
	}
	// The report lists 60 functions: a page for a reader, of whom most are language models with a limited context.
	args := append([]string{"-top", "-output=report"}, pprofOptions(parsed, sampleType, cumulative, 60)...)
	pprofStart.Lock()
	defer pprofStart.Unlock()
	var report pprofReport
	err = driver.PProf(&driver.Options{
		Flagset: &pprofFlags{FlagSet: flag.NewFlagSet("pprof", flag.ContinueOnError), args: append(args, "--", "profile")},
		Fetch:   fetched{"profile": parsed},
		UI:      pprofUI{},
		Writer:  &report,
	})
	if err != nil {
		return "", errStatus{http.StatusUnprocessableEntity, "pprof cannot show this profile: " + err.Error()}
	}
	return "Kinds of values in this profile: " + strings.Join(kinds, ", ") + "\n" + report.String(), nil
}

// pprofOptions are the options of every start of pprof. pprof keeps its
// options for the whole program, so each start names all of those that any
// start sets; otherwise it would inherit them from the start before. The
// kind of value is, unless one is named, the one that the profile names
// as its default, or else its last, as pprof chooses by itself.
func pprofOptions(p *profile.Profile, sampleType string, cumulative bool, functions int) []string {
	if sampleType == "" {
		sampleType = p.DefaultSampleType
	}
	if sampleType == "" && len(p.SampleType) > 0 {
		sampleType = p.SampleType[len(p.SampleType)-1].Type
	}
	sort := "-flat"
	if cumulative {
		sort = "-cum"
	}
	return []string{"-symbolize=none", "-sample_index=" + sampleType, sort, "-nodecount=" + strconv.Itoa(functions)}
}

// pprofReport takes the report that pprof writes to a file.
type pprofReport struct{ bytes.Buffer }

func (r *pprofReport) Open(string) (io.WriteCloser, error) { return r, nil }
func (r *pprofReport) Close() error                        { return nil }

// fetched hands pprof the profiles that the hub already holds, by the
// names its command line gives them.
type fetched map[string]*profile.Profile

func (f fetched) Fetch(source string, _, _ time.Duration) (*profile.Profile, string, error) {
	if f[source] == nil {
		return nil, "", fmt.Errorf("no profile %q", source)
	}
	// pprof changes what it is handed.
	return f[source].Copy(), "", nil
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
