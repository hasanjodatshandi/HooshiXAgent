package architecture_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Clean Architecture layering (ADR-0013): the domain layer must stay free
// of infrastructure concerns and the dependency direction must point
// strictly inward (adapters/application -> domain), never outward.

var domainPackages = []string{
	"internal/contractv1",
	"internal/agent/tunnelstates",
}

// infrastructureImportPrefixes are Go standard-library/external packages
// that represent network, OS, or transport-adapter implementation details a
// pure domain package must not depend on. Pure crypto/encoding logic stays
// allowed.
var infrastructureImportPrefixes = []string{
	"net",
	"net/http",
	"os",
	"syscall",
	"github.com/coder/websocket",
}

func TestDomainPackagesHaveNoInfrastructureImports(t *testing.T) {
	t.Parallel()

	violations := []string{}
	root := repositoryRoot(t)
	for _, domain := range domainPackages {
		domainRoot := filepath.Join(root, filepath.FromSlash(domain))
		entries, err := os.ReadDir(domainRoot)
		if err != nil {
			t.Fatalf("read domain package %s: %v", domain, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(domainRoot, entry.Name())
			rel := domain + "/" + entry.Name()
			if err := inspectDomainImports(path, rel, &violations); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(violations) != 0 {
		t.Fatalf("domain layer imports infrastructure:\n- %s", strings.Join(violations, "\n- "))
	}
}

func inspectDomainImports(path, rel string, violations *[]string) error {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return err
	}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return err
		}
		for _, prefix := range infrastructureImportPrefixes {
			if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
				*violations = append(*violations, rel+" imports "+importPath)
			}
		}
	}
	return nil
}

func TestDomainImportsPointInwardOnly(t *testing.T) {
	t.Parallel()

	violations := []string{}
	root := repositoryRoot(t)
	for _, domain := range domainPackages {
		domainRoot := filepath.Join(root, filepath.FromSlash(domain))
		entries, err := os.ReadDir(domainRoot)
		if err != nil {
			t.Fatalf("read domain package %s: %v", domain, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(domainRoot, entry.Name())
			rel := domain + "/" + entry.Name()
			if err := inspectOutwardImports(path, rel, &violations); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(violations) != 0 {
		t.Fatalf("domain layer depends on outer layers:\n- %s", strings.Join(violations, "\n- "))
	}
}

// inspectOutwardImports rejects domain imports of the Agent/Gateway product
// packages (application/adapter layers) so the dependency rule stays
// strictly inward-pointing.
func inspectOutwardImports(path, rel string, violations *[]string) error {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return err
	}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return err
		}
		if strings.HasPrefix(importPath, modulePath+"/internal/agent") && !strings.HasPrefix(importPath, modulePath+"/internal/agent/tunnelstates") {
			*violations = append(*violations, rel+" imports application layer "+importPath)
		}
		if strings.HasPrefix(importPath, modulePath+"/internal/gateway") {
			*violations = append(*violations, rel+" imports application layer "+importPath)
		}
		if strings.HasPrefix(importPath, modulePath+"/internal/runtimegate") {
			*violations = append(*violations, rel+" imports adapter layer "+importPath)
		}
	}
	return nil
}
