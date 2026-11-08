//go:build ignore

// check-authority-windows counts hand-built authority validity windows in
// non-test Go files under internal/: duration literals passed as the interval
// of a Fresh(observed, until, now, interval) call, or added to a time assigned
// to a ValidUntil/FreshUntil/until name. New sites fail against the checked-in
// baseline; converting sites to identity.Window only lowers it (plan:
// docs/reviews/authority-window-plan-2026-11-08.md). context.WithTimeout and
// WithDeadline I/O bounds are not counted.
//
//	go run scripts/check-authority-windows.go          # check
//	go run scripts/check-authority-windows.go -write   # rewrite the baseline
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const baselinePath = "scripts/authority-windows-baseline.txt"

var units = map[string]bool{"Nanosecond": true, "Microsecond": true, "Millisecond": true, "Second": true, "Minute": true, "Hour": true}

func main() {
	write := flag.Bool("write", false, "rewrite "+baselinePath+" from the current sources")
	flag.Parse()
	sites := map[string][]int{}
	fset := token.NewFileSet()
	err := filepath.WalkDir("internal", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, pos := range fileSites(file) {
			sites[filepath.ToSlash(path)] = append(sites[filepath.ToSlash(path)], fset.Position(pos).Line)
		}
		return nil
	})
	if err != nil {
		fail(err)
	}
	if *write {
		var b strings.Builder
		b.WriteString("# Hand-built authority validity sites per file (scripts/check-authority-windows.go).\n# Only shrinks: convert sites to identity.Window, then run it with -write.\n")
		for _, path := range sortedKeys(sites) {
			fmt.Fprintf(&b, "%s %d\n", path, len(sites[path]))
		}
		if err := os.WriteFile(baselinePath, []byte(b.String()), 0o644); err != nil {
			fail(err)
		}
		fmt.Printf("authority-window baseline: %d sites in %d files\n", total(sites), len(sites))
		return
	}
	baseline, err := readBaseline()
	if err != nil {
		fail(err)
	}
	failed, shrink := false, 0
	for _, path := range sortedKeys(sites) {
		if n := len(sites[path]); n > baseline[path] {
			failed = true
			for _, line := range sites[path] {
				fmt.Printf("%s:%d: duration literal in an authority validity (file has %d, baseline %d); build it with identity.Check(start, identity.Recheck|PolicyObservation|SQLFenced) and Window.Narrow\n", path, line, n, baseline[path])
			}
		}
	}
	for path, n := range baseline {
		if len(sites[path]) < n {
			shrink += n - len(sites[path])
		}
	}
	if failed {
		fmt.Println("authority-window-check failed: new hand-built validity windows (see docs/reviews/authority-window-plan-2026-11-08.md)")
		os.Exit(1)
	}
	if shrink > 0 {
		fmt.Printf("authority-window baseline can shrink by %d: go run scripts/check-authority-windows.go -write\n", shrink)
	}
	fmt.Printf("authority-window-check: %d sites in %d files, none above the baseline\n", total(sites), len(sites))
}

// fileSites returns the positions of the counted duration literals.
func fileSites(file *ast.File) []token.Pos {
	timeName := ""
	for _, spec := range file.Imports {
		if spec.Path.Value == `"time"` {
			timeName = "time"
			if spec.Name != nil {
				timeName = spec.Name.Name
			}
		}
	}
	if timeName == "" || timeName == "_" {
		return nil
	}
	var out []token.Pos
	assigned := func(names []ast.Expr, values []ast.Expr) {
		for i, value := range values {
			if len(names) == len(values) && !validityName(names[i]) || len(names) != len(values) && !slices.ContainsFunc(names, validityName) {
				continue
			}
			out = append(out, addedLiterals(value, timeName)...)
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if calledName(n.Fun) == "Fresh" && len(n.Args) == 4 && durationLiteral(n.Args[3], timeName) {
				out = append(out, n.Args[3].Pos())
			}
		case *ast.AssignStmt:
			assigned(n.Lhs, n.Rhs)
		case *ast.ValueSpec:
			names := make([]ast.Expr, len(n.Names))
			for i, name := range n.Names {
				names[i] = name
			}
			assigned(names, n.Values)
		case *ast.KeyValueExpr:
			assigned([]ast.Expr{n.Key}, []ast.Expr{n.Value})
		}
		return true
	})
	return out
}

// addedLiterals finds x.Add(<duration literal>) in an assigned value, except
// inside context.With* calls, whose deadlines bound I/O, not authority.
func addedLiterals(value ast.Expr, timeName string) []token.Pos {
	var out []token.Pos
	ast.Inspect(value, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if s, ok := call.Fun.(*ast.SelectorExpr); ok {
			if x, ok := s.X.(*ast.Ident); ok && x.Name == "context" && strings.HasPrefix(s.Sel.Name, "With") {
				return false
			}
			if s.Sel.Name == "Add" && len(call.Args) == 1 && durationLiteral(call.Args[0], timeName) {
				out = append(out, call.Args[0].Pos())
			}
		}
		return true
	})
	return out
}

func validityName(e ast.Expr) bool {
	name := ""
	switch e := e.(type) {
	case *ast.Ident:
		name = e.Name
	case *ast.SelectorExpr:
		name = e.Sel.Name
	}
	name = strings.ToLower(name)
	return name == "until" || strings.HasSuffix(name, "validuntil") || strings.HasSuffix(name, "freshuntil")
}

func calledName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// durationLiteral reports a constant expression of number literals and time
// units, such as 5*time.Second; named interval constants do not count.
func durationLiteral(e ast.Expr, timeName string) bool {
	unit := false
	literal := true
	ast.Inspect(e, func(n ast.Node) bool {
		switch n := n.(type) {
		case nil, *ast.BasicLit, *ast.ParenExpr, *ast.BinaryExpr, *ast.UnaryExpr:
			return true
		case *ast.SelectorExpr:
			if x, ok := n.X.(*ast.Ident); ok && x.Name == timeName && units[n.Sel.Name] {
				unit = true
				return false
			}
		case *ast.CallExpr: // time.Duration(5)
			if s, ok := n.Fun.(*ast.SelectorExpr); ok && len(n.Args) == 1 {
				if x, ok := s.X.(*ast.Ident); ok && x.Name == timeName && s.Sel.Name == "Duration" {
					if _, ok := n.Args[0].(*ast.BasicLit); ok {
						return false
					}
				}
			}
		}
		literal = false
		return false
	})
	return unit && literal
}

func readBaseline() (map[string]int, error) {
	f, err := os.Open(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("%w (create it with -write)", err)
	}
	defer f.Close()
	out := map[string]int{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		path, count, ok := strings.Cut(line, " ")
		n, err := strconv.Atoi(count)
		if !ok || err != nil || n <= 0 {
			return nil, fmt.Errorf("%s: malformed line %q", baselinePath, line)
		}
		out[path] = n
	}
	return out, scanner.Err()
}

func sortedKeys(m map[string][]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func total(m map[string][]int) (n int) {
	for _, v := range m {
		n += len(v)
	}
	return n
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "authority-window-check:", err)
	os.Exit(2)
}
