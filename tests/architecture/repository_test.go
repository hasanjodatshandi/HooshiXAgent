package architecture_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path"
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

	entries, err := repositoryEntries(root)
	if err != nil {
		violations = append(violations, fmt.Sprintf("repository listing failed: %v", err))
		return violations
	}

	forbiddenDirs := map[string]struct{}{}
	for _, entry := range entries {
		rel := filepath.ToSlash(entry.rel)
		parts := strings.Split(rel, "/")
		if entry.isDir {
			if _, forbidden := forbiddenImplementationDirs[strings.ToLower(parts[len(parts)-1])]; forbidden {
				forbiddenDirs[rel] = struct{}{}
			}
			continue
		}
		if filepath.Ext(rel) != ".go" {
			continue
		}
		if err := inspectGoImports(filepath.Join(root, filepath.FromSlash(entry.rel)), rel, &violations); err != nil {
			violations = append(violations, fmt.Sprintf("repository inspection failed: %v", err))
			return violations
		}
	}
	for dir := range forbiddenDirs {
		violations = append(violations, fmt.Sprintf("forbidden implementation directory: %s", dir))
	}

	sort.Strings(violations)
	return violations
}

// repositoryEntry is one file or directory the architecture walk must inspect.
type repositoryEntry struct {
	rel   string
	isDir bool
}

// repositoryEntries lists what the architecture boundary must be validated
// against.
//
// In a git work tree the list comes from `git ls-files --cached --others
// --exclude-standard`, so ignored local scratch (build output, the Setup.exe
// payload, runtime state) can never fail the architecture test or mask a real
// violation behind a walk error. The directories of tracked files are derived
// from their paths because git does not record empty directories.
//
// Directories that are not a git work tree — the fixture repositories the
// negative tests build in a temp dir — fall back to a filesystem walk, which is
// the behaviour those tests assert.
func repositoryEntries(root string) ([]repositoryEntry, error) {
	if info, err := os.Stat(filepath.Join(root, ".git")); err == nil && info.IsDir() {
		return gitTrackedEntries(root)
	}
	return walkedEntries(root)
}

func gitTrackedEntries(root string) ([]repositoryEntry, error) {
	command := exec.Command("git", "-C", root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var entries []repositoryEntry
	seen := map[string]struct{}{}
	for _, name := range strings.Split(string(output), "\x00") {
		if name == "" {
			continue
		}
		if _, duplicate := seen[name]; !duplicate {
			seen[name] = struct{}{}
			entries = append(entries, repositoryEntry{rel: name})
		}
		for dir := path.Dir(name); dir != "." && dir != "/"; dir = path.Dir(dir) {
			if _, duplicate := seen[dir]; duplicate {
				continue
			}
			seen[dir] = struct{}{}
			entries = append(entries, repositoryEntry{rel: dir, isDir: true})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	return entries, nil
}

func walkedEntries(root string) ([]repositoryEntry, error) {
	var entries []repositoryEntry
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
		if rel == "." {
			return nil
		}
		entries = append(entries, repositoryEntry{rel: filepath.ToSlash(rel), isDir: entry.IsDir()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	return entries, nil
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
