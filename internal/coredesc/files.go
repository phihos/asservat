package coredesc

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
)

// FilesSuffix is appended to a core's name for the archive of its
// program's files: the executable and the libraries that the core maps, at
// the paths the program saw them. Unpacked, the directory is what a
// debugger needs next to the core (gdb: set sysroot).
const FilesSuffix = ".files.tar"

// Files lists the program files that a described core maps and that are
// found under root: executables and libraries, not the data files a
// program may map as well, which can be of any size and are not needed to
// read stacks. With them come the few files that name the container's
// distribution (debugpkgs.go) and, of a .NET program, its managed
// assemblies (dotnet.go).
func Files(report []byte, root string) []string {
	var fields struct {
		Mappings []struct{ File string }
		Modules  []struct{ File string }
	}
	if json.Unmarshal(report, &fields) != nil {
		return nil
	}
	var files []string
	seen := map[string]bool{}
	add := func(name string) {
		// A mapping of a file that was deleted is named with that word.
		name = strings.TrimSuffix(name, " (deleted)")
		// A name through another directory, as /usr/local/bin/../lib/x, is
		// no path of an archive: the file is kept at the path that the
		// name leads to, where the name finds it once unpacked.
		if strings.HasPrefix(name, "/") && name != pathpkg.Clean(name) {
			name, _ = resolve(root, name)
		}
		if !strings.HasPrefix(name, "/") || seen[name] {
			return
		}
		seen[name] = true
		if file, _ := resolve(root, name); file != "" && isELF(filepath.Join(root, file)) {
			files = append(files, name)
		}
	}
	var mapped []string
	for _, m := range fields.Mappings {
		add(m.File)
		mapped = append(mapped, m.File)
	}
	// The program asks for a library by a name that is often a link to
	// the file that is mapped: a debugger looks for it by that name.
	for _, m := range fields.Modules {
		add(m.File)
	}
	return append(withDistributionFiles(files, root), dotnetFiles(mapped, root)...)
}

// resolve follows the links of a path as the program saw it, within root,
// and returns the path of the file it leads to, on which no part is a
// link, and whether there was a link on the way. It follows them itself,
// part by part: the kernel follows a link to an absolute path from the
// root of the process that asks, and on a node root is /proc/<pid>/root,
// so that a container could lead the agent to the node's own files.
func resolve(root, name string) (file string, link bool) {
	file = "/"
	rest := strings.Split(name, "/")
	// As many links as the kernel follows on one path.
	for links := 0; len(rest) > 0; {
		part := rest[0]
		rest = rest[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			file = filepath.Dir(file)
			continue
		}
		next := filepath.Join(file, part)
		info, err := os.Lstat(filepath.Join(root, next))
		if err != nil {
			return "", link
		}
		if info.Mode()&os.ModeSymlink == 0 {
			file = next
			continue
		}
		target, err := os.Readlink(filepath.Join(root, next))
		if links++; err != nil || links > 40 {
			return "", link
		}
		link = true
		if filepath.IsAbs(target) {
			file = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	return file, link
}

// Mapped stands in for the description of a core that could not be
// described, as far as Files reads one: the files that the core maps. With
// the program's files kept all the same, the hub can describe the core
// later.
func Mapped(core string) []byte {
	type mapping struct {
		File string `json:"file"`
	}
	var report struct {
		Mappings []mapping `json:"mappings"`
	}
	for _, name := range coreFiles(core) {
		report.Mappings = append(report.Mappings, mapping{name})
	}
	listed, _ := json.Marshal(report)
	return listed
}

// isELF tells whether the path is a regular file that starts as an
// executable or library does.
func isELF(path string) bool { return startsWith(path, "\x7fELF") }

// startsWith tells whether the path is a regular file that starts with the
// bytes.
func startsWith(path, start string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, len(start))
	_, err = io.ReadFull(f, magic)
	return err == nil && string(magic) == start
}

// WriteFiles writes the files, found under root, as a tar archive. A name
// that is a link is written as a link to its file, which is written too.
func WriteFiles(w io.Writer, root string, files []string) error {
	archive := tar.NewWriter(w)
	written := map[string]bool{}
	for i := 0; i < len(files); i++ {
		name := files[i]
		if written[name] {
			continue
		}
		written[name] = true
		if file, link := resolve(root, name); link && file != "" {
			to, err := filepath.Rel(filepath.Dir(name), file)
			if err != nil {
				return err
			}
			if err := archive.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Linkname: to, Mode: 0o777, Typeflag: tar.TypeSymlink}); err != nil {
				return err
			}
			files = append(files, file)
			continue
		}
		f, err := os.Open(filepath.Join(root, name))
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err == nil {
			err = archive.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Mode: 0o755, Size: info.Size(), ModTime: info.ModTime(), Typeflag: tar.TypeReg})
		}
		if err == nil {
			// A file that changes meanwhile ends the archive with an error.
			_, err = io.CopyN(archive, f, info.Size())
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	return archive.Close()
}

// ExtractFiles unpacks an archive of program files into the directory dir,
// which then stands for the root that the program saw. It takes regular
// files and links to them only, and none that would land or lead outside
// of dir. size is the
// archive's own: it unpacks to no more, since nothing in it is compressed,
// unless it is made to with files that are mostly holes, which program
// files are not.
func ExtractFiles(r io.Reader, dir string, size int64) error {
	archive := tar.NewReader(r)
	left := size
	for {
		header, err := archive.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// An archive of an earlier Asservat may name a file through another
		// directory (usr/local/bin/../lib/x): it is the file at the path
		// that the name leads to, if that is within the directory.
		name := header.Name
		if !filepath.IsAbs(name) {
			name = pathpkg.Clean(name)
		}
		link := header.Typeflag == tar.TypeSymlink && !filepath.IsAbs(header.Linkname) && fs.ValidPath(pathpkg.Join(pathpkg.Dir(name), header.Linkname))
		if header.Typeflag != tar.TypeReg && !link || !fs.ValidPath(name) {
			return errors.New("the archive holds more than program files: " + header.Name)
		}
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if link {
			err := os.Symlink(header.Linkname, path)
			// The same link a second time, under both of its names in such an earlier archive.
			if to, e := os.Readlink(path); errors.Is(err, fs.ErrExist) && e == nil && to == header.Linkname {
				continue
			}
			if err != nil {
				return err
			}
			continue
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		// The same file a second time, as such an earlier archive holds it
		// under both of its names: the first stands. What else is in the
		// way, a link or a directory, is a fault of the archive.
		if info, e := os.Lstat(path); errors.Is(err, fs.ErrExist) && e == nil && info.Mode().IsRegular() {
			n, err := io.Copy(io.Discard, io.LimitReader(archive, left+1))
			if left -= n; err == nil && left < 0 {
				err = errors.New("the archive unpacks to more than it holds")
			}
			if err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		n, err := io.Copy(f, io.LimitReader(archive, left+1))
		if left -= n; err == nil && left < 0 {
			err = errors.New("the archive unpacks to more than it holds")
		}
		if e := f.Close(); err == nil {
			err = e
		}
		if err != nil {
			return err
		}
	}
}
