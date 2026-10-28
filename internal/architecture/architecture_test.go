package architecture

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCoreImportBoundaries(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, directory := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			for _, imported := range file.Imports {
				name, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					return err
				}
				if (name == "crypto" || strings.HasPrefix(name, "crypto/") || strings.HasPrefix(name, "golang.org/x/crypto")) && !strings.HasPrefix(rel, "internal/crypto/") {
					t.Errorf("%s imports cryptography outside custody boundary: %s", rel, name)
				}
				if strings.HasPrefix(name, "github.com/ctlplne/freightctl/ee/") || strings.Contains(strings.ToLower(name), "sqlite") || strings.Contains(strings.ToLower(name), "redis") {
					t.Errorf("%s imports forbidden core dependency: %s", rel, name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
