package architecture_test

import (
	"go/parser"
	"go/token"
	"io/fs"
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
	"internal/contractv2",
	"internal/agent/tunnelstates",
	"internal/agent/agentbudget",
	"internal/gateway/gatewayresources",
}

// applicationPackages are the declared application/adapter packages: the
// layer allowed to import infrastructure and reach outward. The classification
// gate below forces every package under internal/ to appear in exactly one of
// the two lists, which is what stops a newly added package from escaping the
// layering rules by being unknown to them.
var applicationPackages = []string{
	"internal/agent",
	"internal/agent/supervisor",
	"internal/agent/svc",
	"internal/agent/webapp",
	"internal/connectgui",
	"internal/connector",
	"internal/enrollment",
	"internal/gateway",
	"internal/tray",
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

	forEachDomainFile(t, inspectDomainImports, "domain layer imports infrastructure")
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

	forEachDomainFile(t, inspectOutwardImports, "domain layer depends on outer layers")
}

// forEachDomainFile applies one rule to every non-test Go file of every
// declared domain package. The walk is recursive, so a package nested inside a
// domain directory is covered by the rule instead of silently sitting outside
// it.
func forEachDomainFile(t *testing.T, rule func(path, rel string, violations *[]string) error, failure string) {
	t.Helper()

	root := repositoryRoot(t)
	violations := []string{}
	for _, domain := range domainPackages {
		domainRoot := filepath.Join(root, filepath.FromSlash(domain))
		err := filepath.WalkDir(domainRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			return rule(path, filepath.ToSlash(rel), &violations)
		})
		if err != nil {
			t.Fatalf("walk domain package %s: %v", domain, err)
		}
	}
	if len(violations) != 0 {
		t.Fatalf("%s:\n- %s", failure, strings.Join(violations, "\n- "))
	}
}

// TestEveryInternalPackageIsClassifiedByTheLayeringGate proves the gate knows
// the repository it is guarding: each package under internal/ must be declared
// either domain or application, and each declared package must still exist.
// Without this, adding a package — or deleting one and leaving its entry behind
// — would quietly narrow what the layering rules look at.
func TestEveryInternalPackageIsClassifiedByTheLayeringGate(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	domain := declaredPackages(domainPackages)
	application := declaredPackages(applicationPackages)
	for _, declared := range domainPackages {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(declared))); err != nil {
			t.Fatalf("declared domain package %s is unreadable: %v", declared, err)
		}
	}
	for _, declared := range applicationPackages {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(declared))); err != nil {
			t.Fatalf("declared application package %s is unreadable: %v", declared, err)
		}
	}

	var unclassified []string
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		if entry.Name() == "testdata" {
			return fs.SkipDir
		}
		isPackage, err := directoryHasGoFiles(path)
		if err != nil {
			return err
		}
		if !isPackage {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		switch {
		case domain[name] && application[name]:
			unclassified = append(unclassified, name+" (declared both domain and application)")
		case !domain[name] && !application[name]:
			unclassified = append(unclassified, name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(unclassified) != 0 {
		t.Fatalf("packages under internal/ that the layering gate does not classify:\n- %s\nAdd each one to domainPackages or applicationPackages in this file so the ADR-0013 rules cover it.", strings.Join(unclassified, "\n- "))
	}
}

func declaredPackages(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

func directoryHasGoFiles(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			return true, nil
		}
	}
	return false, nil
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
