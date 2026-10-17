// Package migrations contains the reviewed immutable product schema sources.
// Runtime callers cannot choose a directory or provide SQL. Query definitions
// in the queries subdirectory are deliberately not part of this filesystem.
package migrations

import (
	"embed"
	"io/fs"
)

//go:embed *.sql
var files embed.FS

func Files() fs.FS { return files }
