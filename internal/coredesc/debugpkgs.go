package coredesc

import (
	"bufio"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// No debuginfod server knows the programs of RHEL's universal base images,
// Rocky, Alma, Amazon Linux or Alpine, but these distributions publish
// their debug information as packages. This file finds the packages for
// the stripped files of a core, downloads them and unpacks their debug
// files, for gdb to read as it reads those under /usr/lib/debug.

// debugSources are the places that debug packages are fetched from.
type debugSources struct {
	// RPM names, by the ID of a distribution's /etc/os-release, its
	// repositories of debug packages: the directories that hold
	// repodata/repomd.xml, or a mirror.list that names one. {version} is
	// the release's VERSION_ID, {major} its first number, {arch} the
	// processor as RPM names it. A repository that does not exist for a
	// release is passed over.
	RPM map[string][]string
	// Alpine is the mirror of Alpine's packages.
	Alpine string
}

var publicDebugSources = debugSources{
	RPM: map[string][]string{
		// The universal base images' repositories list the latest build of
		// each package only: an image with an older build finds nothing.
		"rhel": {
			"https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi{major}/{major}/{arch}/baseos/debug/",
			"https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi{major}/{major}/{arch}/appstream/debug/",
		},
		// Rocky lists the latest builds of its current releases under pub
		// and the last builds of earlier ones in its vault.
		"rocky": {
			"https://dl.rockylinux.org/pub/rocky/{version}/BaseOS/{arch}/debug/tree/",
			"https://dl.rockylinux.org/pub/rocky/{version}/AppStream/{arch}/debug/tree/",
			"https://dl.rockylinux.org/vault/rocky/{version}/BaseOS/{arch}/debug/tree/",
			"https://dl.rockylinux.org/vault/rocky/{version}/AppStream/{arch}/debug/tree/",
		},
		// Alma keeps every build of a release, the current ones too, in its vault.
		"almalinux": {
			"https://repo.almalinux.org/vault/{version}/BaseOS/debug/{arch}/",
			"https://repo.almalinux.org/vault/{version}/AppStream/debug/{arch}/",
		},
		// Amazon Linux 2023 lists every build it has published.
		"amzn": {"https://cdn.amazonlinux.com/al{version}/core/mirrors/latest/debuginfo/{arch}/mirror.list"},
	},
	Alpine: "https://dl-cdn.alpinelinux.org/alpine",
}

const (
	// A server that does not answer, or sends nothing more, for this long
	// is given up, as gdb gives up a debuginfod server (DEBUGINFOD_TIMEOUT
	// in analysis.go): a cluster may have no way out, and the description
	// of a core must not wait for one.
	debugPackageWait = 10 * time.Second
	// A repository's index of build IDs is asked for anew after a day:
	// the distributions publish updates on working days, not by the hour,
	// and the index of Amazon Linux is a download of 5 MiB.
	debugIndexAge = 24 * time.Hour
	// What was downloaded and not used for a week is removed, as the
	// debuginfod client does with its downloads next to these.
	debugPackageAge = 7 * 24 * time.Hour
)

var errNotPublished = errors.New("not published")

// distributionFiles are the files, besides its programs, by which the
// debug packages of a container's distribution are found: its release, and
// on Alpine the list of installed packages with their files.
var distributionFiles = []string{"/etc/os-release", "/lib/apk/db/installed", "/usr/lib/apk/db/installed"}

// withDistributionFiles adds those of the distribution's files that are
// under root to a core's program files, for the hub to describe the core
// again as the agent did.
func withDistributionFiles(files []string, root string) []string {
	if len(files) == 0 {
		return files
	}
	for _, name := range distributionFiles {
		if file, _ := resolve(root, name); file != "" {
			files = append(files, name)
		}
	}
	return files
}

// debugDirs returns directories with the debug files of the stripped
// programs and libraries that the core maps, from the debug packages of
// the distribution found under root. Their layout is that of
// /usr/lib/debug. It fetches only where debuginfod servers are named: the
// operator's one switch for asking others about the programs that run
// here. What it does not find is described without.
func (d Describer) debugDirs(ctx context.Context, core, root string) []string {
	if d.DebuginfodURLs == "" || root == "" {
		return nil
	}
	sources := d.sources
	if sources == nil {
		sources = &publicDebugSources
	}
	release := osRelease(root)
	repositories := sources.RPM[release["ID"]]
	if repositories == nil && release["ID"] != "alpine" {
		return nil
	}
	// The packages are unpacked with bsdtar; where it is not installed,
	// cores are described without.
	if _, err := exec.LookPath("bsdtar"); err != nil {
		return nil
	}
	// The stripped files with their build IDs, by the name the program
	// mapped them under and by the path that leads to without links: a
	// package's list of files may have either.
	stripped := map[string]string{}
	arch := ""
	for _, name := range coreFiles(core) {
		name = pathpkg.Clean("/" + strings.TrimSuffix(name, " (deleted)"))
		path, _ := resolve(root, name)
		if path == "" {
			continue
		}
		file, err := elf.Open(filepath.Join(root, path))
		if err != nil {
			continue
		}
		if file.Section(".debug_info") == nil {
			stripped[path], stripped[name] = buildID(file), buildID(file)
			arch = map[elf.Machine]string{elf.EM_X86_64: "x86_64", elf.EM_AARCH64: "aarch64"}[file.Machine]
		}
		file.Close()
	}
	// What the container says of itself becomes part of addresses and of
	// names in the cache: only what reads as a name or a version is taken.
	// The repositories are laid out by machine: for another than the two
	// known here there is nothing to ask for.
	if len(stripped) == 0 || arch == "" || !plainName.MatchString(release["ID"]) || !plainName.MatchString(release["VERSION_ID"]) {
		return nil
	}
	f := debugFetcher{ctx: ctx, cache: filepath.Join(d.Scratch, "debugpkgs")}
	if err := os.MkdirAll(f.cache, 0o700); err != nil {
		return nil
	}
	f.sweep()
	// The packages to unpack: for each a name in the cache and the places
	// it may be at.
	var packages map[string][]string
	var err, looked error
	if repositories != nil {
		major, _, _ := strings.Cut(release["VERSION_ID"], ".")
		fill := strings.NewReplacer("{version}", release["VERSION_ID"], "{major}", major, "{arch}", arch)
		packages = map[string][]string{}
		for _, repository := range repositories {
			var found []string
			// A repository that fails ends the looking, not the fetching
			// of what the ones before it found.
			if found, looked = f.lookup(fill.Replace(repository), stripped); looked != nil {
				break
			}
			for _, rpm := range found {
				packages[release["ID"]+"-"+pathpkg.Base(rpm)] = []string{rpm}
			}
		}
	} else {
		packages = apkDebugPackages(root, sources.Alpine, release["VERSION_ID"], stripped)
	}
	var dirs []string
	for name, urls := range packages {
		if err != nil {
			break
		}
		var dir string
		if dir, err = f.unpack(name, urls); dir != "" {
			dirs = append(dirs, dir)
		}
	}
	if err = errors.Join(looked, err); err != nil {
		// One server that fails is not asked for the rest.
		slog.Warn("debug packages not fetched", "core", core, "distribution", release["ID"], "error", err)
	}
	return dirs
}

// osRelease reads the fields of the /etc/os-release under root.
func osRelease(root string) map[string]string {
	fields := map[string]string{}
	path, _ := resolve(root, "/etc/os-release")
	content, err := os.ReadFile(filepath.Join(root, path))
	if path == "" || err != nil {
		return fields
	}
	for _, line := range strings.Split(string(content), "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			fields[key] = strings.Trim(value, `"'`)
		}
	}
	return fields
}

// coreMapping is a part of a file that a core says was mapped: the
// addresses it was at and where in the file they begin.
type coreMapping struct {
	start, end, offset uint64
	name               string
}

// coreMappings lists the mappings of files in a core, from the note that
// the kernel and gcore write into it (NT_FILE), on a 64-bit machine.
func coreMappings(file *elf.File) []coreMapping {
	var mappings []coreMapping
	for _, segment := range file.Progs {
		if segment.Type != elf.PT_NOTE {
			continue
		}
		notes, err := io.ReadAll(segment.Open())
		if err != nil {
			return nil
		}
		// A note: the sizes of its name and content, its type, then both,
		// each filled up to four bytes.
		for len(notes) >= 12 {
			name, size, kind := int(file.ByteOrder.Uint32(notes)), int(file.ByteOrder.Uint32(notes[4:])), file.ByteOrder.Uint32(notes[8:])
			start := 12 + (name+3)&^3
			if name < 0 || size < 0 || start+size > len(notes) {
				break
			}
			content := notes[start : start+size]
			notes = notes[min(start+(size+3)&^3, len(notes)):]
			const ntFile = 0x46494c45
			if kind != ntFile || len(content) < 16 {
				continue
			}
			// The count of mappings and the page size; for each mapping
			// its first address, the one after its last and the page of
			// the file it begins at; then the names, each ended by a zero
			// byte.
			count, page := file.ByteOrder.Uint64(content), file.ByteOrder.Uint64(content[8:])
			if count > uint64(len(content)-16)/24 {
				continue
			}
			names := strings.Split(string(content[16+24*count:]), "\x00")
			for i := range min(count, uint64(len(names))) {
				at := content[16+24*i:]
				mappings = append(mappings, coreMapping{file.ByteOrder.Uint64(at), file.ByteOrder.Uint64(at[8:]), file.ByteOrder.Uint64(at[16:]) * page, names[i]})
			}
		}
	}
	return mappings
}

// coreFiles lists the files that a core maps.
func coreFiles(core string) []string {
	file, err := elf.Open(core)
	if err != nil {
		return nil
	}
	defer file.Close()
	var files []string
	seen := map[string]bool{}
	for _, m := range coreMappings(file) {
		if m.name != "" && !seen[m.name] {
			seen[m.name] = true
			files = append(files, m.name)
		}
	}
	return files
}

// buildID is the build ID that the linker gave a file, in hexadecimal;
// empty if it gave none.
func buildID(file *elf.File) string {
	section := file.Section(".note.gnu.build-id")
	if section == nil {
		return ""
	}
	note, err := section.Data()
	if err != nil || len(note) < 12 {
		return ""
	}
	name, size := int(file.ByteOrder.Uint32(note)), int(file.ByteOrder.Uint32(note[4:]))
	start := 12 + (name+3)&^3
	if name < 0 || size < 0 || start+size > len(note) {
		return ""
	}
	return hex.EncodeToString(note[start : start+size])
}

// apkDebugPackages names the debug packages of the Alpine packages that
// own the stripped files, by the list of installed packages under root.
// Alpine builds one debug package, <origin>-dbg, for all packages of one
// source, and only for some sources; its mirror keeps the latest revision
// of each only. So many are not there, which is told when they are asked
// for.
func apkDebugPackages(root, mirror, version string, stripped map[string]string) map[string][]string {
	packages := map[string][]string{}
	var installed []byte
	for _, name := range distributionFiles[1:] {
		if path, _ := resolve(root, name); path != "" && installed == nil {
			installed, _ = os.ReadFile(filepath.Join(root, path))
		}
	}
	// A release 3.22.1 is of the branch v3.22; one of the edge branch is
	// named after the release to come, as 3.23.0_alpha20250612.
	branch := "edge"
	if parts := strings.Split(version, "."); len(parts) == 3 && !strings.Contains(version, "_") {
		branch = "v" + parts[0] + "." + parts[1]
	}
	// A package's lines begin with a letter for what they say: its
	// version (V), architecture (A) and origin (o), then its directories
	// (F) and the files in each (R). An empty line ends the package.
	for _, lines := range strings.Split(string(installed), "\n\n") {
		fields := map[byte]string{}
		owns := false
		for _, line := range strings.Split(lines, "\n") {
			if len(line) < 2 || line[1] != ':' {
				continue
			}
			if _, is := stripped[pathpkg.Join("/", fields['F'], line[2:])]; line[0] == 'R' && is {
				owns = true
			}
			fields[line[0]] = line[2:]
		}
		if origin := fields['o']; owns && plainName.MatchString(origin) && plainName.MatchString(fields['V']) && plainName.MatchString(fields['A']) && plainName.MatchString(branch) {
			name, arch := origin+"-dbg-"+fields['V'], fields['A']
			packages["alpine-"+branch+"-"+arch+"-"+name] = []string{
				mirror + "/" + branch + "/main/" + arch + "/" + name + ".apk",
				mirror + "/" + branch + "/community/" + arch + "/" + name + ".apk",
			}
		}
	}
	return packages
}

// plainName is a name or a version as distributions write them: nothing
// that leads elsewhere in an address or a directory.
var plainName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]*$`)

// debugFetcher downloads debug packages into a directory that keeps them
// for the next core.
type debugFetcher struct {
	ctx   context.Context
	cache string
}

// sweep removes what was not used for a week.
func (f debugFetcher) sweep() {
	entries, _ := os.ReadDir(f.cache)
	for _, entry := range entries {
		if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) > debugPackageAge {
			os.RemoveAll(filepath.Join(f.cache, entry.Name()))
		}
	}
}

// waited ends a download whose server sends nothing for too long.
type waited struct {
	io.ReadCloser
	wait *time.Timer
	end  context.CancelFunc
}

func (w waited) Close() error {
	w.end()
	return w.ReadCloser.Close()
}

func (w waited) Read(b []byte) (int, error) {
	w.wait.Reset(debugPackageWait)
	defer w.wait.Stop()
	return w.ReadCloser.Read(b)
}

// get asks for a file. One that the server does not have is errNotPublished.
func (f debugFetcher) get(address string) (io.ReadCloser, error) {
	ctx, cancel := context.WithCancel(f.ctx)
	wait := time.AfterFunc(debugPackageWait, cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	response, err := http.DefaultClient.Do(request)
	wait.Stop()
	if err != nil {
		cancel()
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		cancel()
		// A file that is not there is forbidden on Amazon's servers.
		if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusForbidden {
			return nil, errNotPublished
		}
		return nil, fmt.Errorf("%s: %s", address, response.Status)
	}
	return waited{response.Body, wait, cancel}, nil
}

// unpack returns the directory of debug files of a package, which it
// downloads from the first of the places that has it unless the cache
// holds it under the name. A package that is nowhere leaves an empty
// directory there and is asked for again when that is swept.
func (f debugFetcher) unpack(name string, urls []string) (string, error) {
	path := filepath.Join(f.cache, name)
	dir := filepath.Join(path, "usr/lib/debug")
	if _, err := os.Stat(dir); err == nil {
		// Also what an Asservat before the names by build ID unpacked.
		if _, err := os.Stat(filepath.Join(dir, ".build-id")); err != nil {
			linkByBuildID(dir)
		}
		now := time.Now()
		return dir, os.Chtimes(path, now, now)
	}
	if _, err := os.Stat(path); err == nil {
		return "", nil
	}
	unpacked, err := os.MkdirTemp(f.cache, "unpack-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(unpacked)
	for _, address := range urls {
		body, err := f.get(address)
		if err == errNotPublished {
			continue
		}
		if err != nil {
			return "", err
		}
		// bsdtar reads an RPM and an Alpine package alike, and takes
		// nothing that would land outside of the directory. The debug
		// files are named with ./ in the one and without in the other.
		cmd := exec.CommandContext(f.ctx, "bsdtar", "-x", "-f", "-", "-C", unpacked, "--include", "usr/lib/debug/*", "--include", "./usr/lib/debug/*")
		cmd.Stdin = body
		output, err := cmd.CombinedOutput()
		body.Close()
		if err != nil {
			return "", fmt.Errorf("%s: bsdtar: %w: %s", address, err, tail(output))
		}
		break
	}
	linkByBuildID(filepath.Join(unpacked, "usr/lib/debug"))
	// Another description may have unpacked the same meanwhile.
	if err := os.Rename(unpacked, path); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	if _, err := os.Stat(dir); err != nil {
		return "", nil
	}
	return dir, nil
}

// linkByBuildID gives every debug file under dir a name by its build ID,
// as the debug packages of RPMs have them and Alpine's have not. gdb finds
// a debug file by that name whatever the path of the program's file is: by
// the file's own path it looks in the wrong place where it reads the file
// through a link, as it does in its view of the root (analysis.go).
func linkByBuildID(dir string) {
	filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.Type().IsRegular() || !strings.HasSuffix(path, ".debug") {
			return nil
		}
		file, err := elf.Open(path)
		if err != nil {
			return nil
		}
		id := buildID(file)
		file.Close()
		if len(id) < 3 {
			return nil
		}
		name := filepath.Join(dir, ".build-id", id[:2], id[2:]+".debug")
		if to, err := filepath.Rel(filepath.Dir(name), path); err == nil && os.MkdirAll(filepath.Dir(name), 0o700) == nil {
			os.Symlink(to, name) // the package's own name of the kind stays
		}
		return nil
	})
}

// lookup returns the addresses of the debug packages that a repository of
// RPMs has for the files' build IDs. It reads them from an index of the
// repository's build IDs that it keeps in the cache.
func (f debugFetcher) lookup(repository string, files map[string]string) ([]string, error) {
	sum := sha256.Sum256([]byte(repository))
	index := filepath.Join(f.cache, "index-"+hex.EncodeToString(sum[:8]))
	if info, err := os.Stat(index); err != nil || time.Since(info.ModTime()) > debugIndexAge {
		if err := f.refresh(repository, index); err != nil {
			return nil, err
		}
	}
	file, err := os.Open(index)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	ids := map[string]bool{}
	for _, id := range files {
		ids[id] = id != ""
	}
	var found []string
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		if id, rpm, _ := strings.Cut(lines.Text(), " "); ids[id] {
			found = append(found, rpm)
		}
	}
	return found, lines.Err()
}

// refresh writes the index of a repository: a line with the checksum of
// the repository's list of packages, then a line for each build ID with
// the address of the package that holds its debug file. The list is
// downloaded only when the repository says that it changed; a repository
// that does not exist has an empty index.
func (f debugFetcher) refresh(repository, index string) error {
	base, err := url.Parse(repository)
	if err != nil {
		return err
	}
	var checksum, location string
	var body io.ReadCloser
	if strings.HasSuffix(repository, "mirror.list") {
		// The list names the repository on its first line.
		if body, err = f.get(repository); err == nil {
			line, _ := bufio.NewReader(body).ReadString('\n')
			body.Close()
			base, err = url.Parse(strings.TrimSpace(line))
		}
	}
	if err == nil {
		body, err = f.get(base.JoinPath("repodata/repomd.xml").String())
	}
	if err != nil && err != errNotPublished {
		return err
	}
	if err == nil {
		var lists struct {
			Data []struct {
				Type     string `xml:"type,attr"`
				Checksum string `xml:"checksum"`
				Location struct {
					Href string `xml:"href,attr"`
				} `xml:"location"`
			} `xml:"data"`
		}
		err = xml.NewDecoder(body).Decode(&lists)
		body.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", repository, err)
		}
		for _, list := range lists.Data {
			if list.Type == "primary" {
				checksum, location = list.Checksum, list.Location.Href
			}
		}
	}
	now := time.Now()
	if old, err := os.Open(index); err == nil {
		line, _ := bufio.NewReader(old).ReadString('\n')
		old.Close()
		if strings.TrimSpace(line) == checksum {
			return os.Chtimes(index, now, now)
		}
	}
	out, err := os.CreateTemp(f.cache, "unpack-*")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	lines := bufio.NewWriter(out)
	fmt.Fprintln(lines, checksum)
	if location != "" {
		err = f.buildIDs(base.JoinPath(location), base, lines)
	}
	if e := lines.Flush(); err == nil {
		err = e
	}
	if e := out.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(out.Name(), index)
}

// buildIDs reads a repository's list of packages and writes a line for
// each build ID that a package says it has the debug file of
// ("debuginfo(build-id) = <id>"), with the package's address. The list is
// compressed with gzip, zstd or xz, which bsdcat all reads.
func (f debugFetcher) buildIDs(list, base *url.URL, w io.Writer) error {
	body, err := f.get(list.String())
	if err != nil {
		return err
	}
	defer body.Close()
	cmd := exec.CommandContext(f.ctx, "bsdcat")
	cmd.Stdin = body
	plain, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	read := func() error {
		rpm := ""
		for packages := xml.NewDecoder(plain); ; {
			token, err := packages.Token()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			element, ok := token.(xml.StartElement)
			if !ok {
				continue
			}
			attribute := func(name string) string {
				for _, a := range element.Attr {
					if a.Name.Local == name {
						return a.Value
					}
				}
				return ""
			}
			// A package names its file before what it provides.
			switch {
			case element.Name.Local == "location":
				rpm = base.JoinPath(attribute("href")).String()
			case element.Name.Local == "entry" && attribute("name") == "debuginfo(build-id)":
				fmt.Fprintln(w, attribute("ver"), rpm)
			}
		}
	}
	err = read()
	io.Copy(io.Discard, plain)
	if e := cmd.Wait(); err == nil && e != nil {
		err = fmt.Errorf("bsdcat: %w", e)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", list, err)
	}
	return nil
}
