package architecture_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/hasanjodatshandi/HooshiXAgent"

var forbiddenImplementationDirs = map[string]struct{}{
	"account":       {},
	"accounts":      {},
	"billing":       {},
	"control-panel": {},
	"control_panel": {},
	"control-plane": {},
	"control_plane": {},
	"controlpanel":  {},
	"controlplane":  {},
	"migrations":    {},
	"quota":         {},
	"quotas":        {},
	"tenant":        {},
	"tenants":       {},
	"user":          {},
	"users":         {},
}

func TestRepositoryArchitecture(t *testing.T) {
	t.Parallel()

	violations := validateRepository(t, repositoryRoot(t))
	if len(violations) != 0 {
		t.Fatalf("architecture violations:\n- %s", strings.Join(violations, "\n- "))
	}
}

func TestArchitectureRejectsControlPlaneImplementationDirectory(t *testing.T) {
	t.Parallel()

	root := newFixtureRepository(t)
	mustMkdirAll(t, filepath.Join(root, "internal", "controlplane"))

	violations := validateRepository(t, root)
	assertViolationContains(t, violations, "forbidden implementation directory")
}

func TestArchitectureRejectsAgentGatewayCrossImport(t *testing.T) {
	t.Parallel()

	root := newFixtureRepository(t)
	mustWriteFile(t, filepath.Join(root, "internal", "agent", "cross.go"), `package agent

import _ "github.com/hasanjodatshandi/HooshiXAgent/internal/gateway"
`)

	violations := validateRepository(t, root)
	assertViolationContains(t, violations, "agent must not import gateway")
}

func TestArchitectureRejectsGatewayAgentCrossImport(t *testing.T) {
	t.Parallel()

	root := newFixtureRepository(t)
	mustWriteFile(t, filepath.Join(root, "internal", "gateway", "cross.go"), `package gateway

import _ "github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
`)

	violations := validateRepository(t, root)
	assertViolationContains(t, violations, "gateway must not import agent")
}

func TestArchitectureRejectsControlPlanePackageImport(t *testing.T) {
	t.Parallel()

	root := newFixtureRepository(t)
	mustWriteFile(t, filepath.Join(root, "internal", "gateway", "control.go"), `package gateway

import _ "github.com/hasanjodatshandi/HooshiXAgent/internal/tenants"
`)

	violations := validateRepository(t, root)
	assertViolationContains(t, violations, "forbidden Control Panel package import")
}

func validateRepository(t *testing.T, root string) []string {
	t.Helper()

	var violations []string
	for _, required := range []string{
		"go.mod",
		filepath.Join("internal", "agent"),
		filepath.Join("internal", "gateway"),
		"contracts",
	} {
		if _, err := os.Stat(filepath.Join(root, required)); err != nil {
			violations = append(violations, fmt.Sprintf("required repository boundary missing: %s", filepath.ToSlash(required)))
		}
	}

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if entry.IsDir() {
			if _, forbidden := forbiddenImplementationDirs[strings.ToLower(entry.Name())]; forbidden {
				violations = append(violations, fmt.Sprintf("forbidden implementation directory: %s", filepath.ToSlash(rel)))
			}
			return nil
		}

		if filepath.Ext(entry.Name()) != ".go" {
			return nil
		}
		if err := inspectGoImports(path, rel, &violations); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		violations = append(violations, fmt.Sprintf("repository walk failed: %v", err))
	}

	sort.Strings(violations)
	return violations
}

func inspectGoImports(path, rel string, violations *[]string) error {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return fmt.Errorf("parse %s: %w", rel, err)
	}

	relSlash := filepath.ToSlash(rel)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return fmt.Errorf("unquote import in %s: %w", rel, err)
		}

		if strings.HasPrefix(relSlash, "internal/agent/") && strings.HasPrefix(importPath, modulePath+"/internal/gateway") {
			*violations = append(*violations, fmt.Sprintf("agent must not import gateway: %s imports %s", relSlash, importPath))
		}
		if strings.HasPrefix(relSlash, "internal/gateway/") && strings.HasPrefix(importPath, modulePath+"/internal/agent") {
			*violations = append(*violations, fmt.Sprintf("gateway must not import agent: %s imports %s", relSlash, importPath))
		}

		lower := strings.ToLower(importPath)
		for forbidden := range forbiddenImplementationDirs {
			if strings.Contains(lower, "/"+forbidden) {
				*violations = append(*violations, fmt.Sprintf("forbidden Control Panel package import: %s imports %s", relSlash, importPath))
				break
			}
		}
	}
	return nil
}

func repositoryRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve architecture test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("cannot resolve repository root: %v", err)
	}
	return root
}

func newFixtureRepository(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "go.mod"), "module "+modulePath+"\n\ngo 1.27.0\n")
	mustMkdirAll(t, filepath.Join(root, "internal", "agent"))
	mustMkdirAll(t, filepath.Join(root, "internal", "gateway"))
	mustMkdirAll(t, filepath.Join(root, "contracts"))
	return root
}

func assertViolationContains(t *testing.T, violations []string, want string) {
	t.Helper()
	for _, violation := range violations {
		if strings.Contains(violation, want) {
			return
		}
	}
	t.Fatalf("expected violation containing %q; got %v", want, violations)
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	mustMkdirAll(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
