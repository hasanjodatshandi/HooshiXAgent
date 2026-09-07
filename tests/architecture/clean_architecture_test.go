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
	"internal/agent/agentbudget",
	"internal/gateway/gatewayresources",
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

// domainSubpackages lists the pure-domain package prefixes that live under a
// product boundary; domain files may import other domain packages but never
// an application/adapter (product) package.
var domainSubpackages = []string{
	"internal/agent/tunnelstates",
	"internal/agent/agentbudget",
	"internal/gateway/gatewayresources",
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
		isDomain := false
		for _, domain := range domainSubpackages {
			if strings.HasPrefix(importPath, modulePath+"/"+domain) {
				isDomain = true
				break
			}
		}
		if strings.HasPrefix(importPath, modulePath+"/internal/agent") && !isDomain {
			*violations = append(*violations, rel+" imports application layer "+importPath)
		}
		if strings.HasPrefix(importPath, modulePath+"/internal/gateway") && !isDomain {
			*violations = append(*violations, rel+" imports application layer "+importPath)
		}
		if strings.HasPrefix(importPath, modulePath+"/tests") {
			*violations = append(*violations, rel+" imports test layer "+importPath)
		}
	}
	return nil
}
