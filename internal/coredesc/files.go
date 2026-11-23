package coredesc

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
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
	}
	if json.Unmarshal(report, &fields) != nil {
		return nil
	}
	var files []string
	seen := map[string]bool{}
	for _, m := range fields.Mappings {
		// A mapping of a file that was deleted is named with that word.
		name := strings.TrimSuffix(m.File, " (deleted)")
		if !strings.HasPrefix(name, "/") || seen[name] {
			continue
		}
		seen[name] = true
		if isELF(filepath.Join(root, name)) {
			files = append(files, name)
		}
	}
	return files
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

// WriteFiles writes the files, found under root, as a tar archive.
func WriteFiles(w io.Writer, root string, files []string) error {
	archive := tar.NewWriter(w)
	for _, name := range files {
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
// files only, and none that would land outside of dir.
func ExtractFiles(r io.Reader, dir string) error {
	archive := tar.NewReader(r)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeReg || !fs.ValidPath(header.Name) {
			return errors.New("the archive holds more than program files: " + header.Name)
		}
		path := filepath.Join(dir, header.Name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, archive)
		if e := f.Close(); err == nil {
			err = e
		}
		if err != nil {
			return err
		}
	}
}
