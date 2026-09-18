package architecture_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseFinalizationChecksOutVerifiedSource(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	_, rest, ok := strings.Cut(workflow, "\n  finalize:")
	if !ok {
		t.Fatal("finalize job missing")
	}
	job, _, _ := strings.Cut(rest, "\n  attest:")
	checkout := strings.Index(job, "uses: actions/checkout@")
	script := strings.Index(job, "bash scripts/release/supply-chain-artifacts.sh")
	if checkout < 0 || script < checkout || !strings.Contains(job, "ref: ${{ needs.policy.outputs.release_sha }}") {
		t.Fatal("finalize must checkout the verified source before invoking repository scripts")
	}
	if !strings.Contains(job, "persist-credentials: false") {
		t.Fatal("finalize checkout must not retain credentials")
	}
	if strings.Contains(workflow, "release_version='${{ inputs.version }}'") {
		t.Fatal("workflow input interpolated into shell source")
	}
}
