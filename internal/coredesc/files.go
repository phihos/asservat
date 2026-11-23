package coredesc

import (
	"archive/tar"
	"bytes"
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
// read stacks.
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
		if !strings.HasPrefix(name, "/") || seen[name] {
			return
		}
		seen[name] = true
		if file, _ := resolve(root, name); file != "" && isELF(filepath.Join(root, file)) {
			files = append(files, name)
		}
	}
	for _, m := range fields.Mappings {
		add(m.File)
	}
	// The program asks for a library by a name that is often a link to
	// the file that is mapped: a debugger looks for it by that name.
	for _, m := range fields.Modules {
		add(m.File)
	}
	return files
}

// resolve follows the links of a path as the program saw it, within root,
// and returns the path of the file it leads to and whether name is a link.
func resolve(root, name string) (file string, link bool) {
	file = filepath.Clean("/" + name)
	// As many links in a row as the kernel follows.
	for range 40 {
		info, err := os.Lstat(filepath.Join(root, file))
		if err != nil {
			return "", link
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return file, link
		}
		target, err := os.Readlink(filepath.Join(root, file))
		if err != nil {
			return "", link
		}
		link = true
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(file), target)
		}
		file = filepath.Clean("/" + target)
	}
	return "", link
}

// isELF tells whether the path is a regular file that starts as an
// executable or library does.
func isELF(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	_, err = io.ReadFull(f, magic)
	return err == nil && bytes.Equal(magic, []byte("\x7fELF"))
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
		link := header.Typeflag == tar.TypeSymlink && !filepath.IsAbs(header.Linkname) && fs.ValidPath(pathpkg.Join(pathpkg.Dir(header.Name), header.Linkname))
		if header.Typeflag != tar.TypeReg && !link || !fs.ValidPath(header.Name) {
			return errors.New("the archive holds more than program files: " + header.Name)
		}
		path := filepath.Join(dir, header.Name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if link {
			if err := os.Symlink(header.Linkname, path); err != nil {
				return err
			}
			continue
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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
