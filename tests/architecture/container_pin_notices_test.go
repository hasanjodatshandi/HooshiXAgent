package architecture_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The notices file is what an operator or auditor reads to learn which images a
// Gateway deployment is built from and runs. scripts/ci/supply-chain.sh proves
// the Dockerfile and Compose pins are immutable; nothing proved the disclosure
// named those same pins, so a bump could leave THIRD_PARTY_NOTICES describing an
// image the product no longer uses.

var disclosedImageRef = regexp.MustCompile(`[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{8,64}`)

func TestThirdPartyNoticesDiscloseThePinnedImages(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	notices := readRepositoryFile(t, root, "THIRD_PARTY_NOTICES")

	pinned := append(
		regexp.MustCompile(`(?m)^FROM\s+(\S+)`).FindAllStringSubmatch(readRepositoryFile(t, root, filepath.Join("deploy", "gateway", "Dockerfile")), -1),
		regexp.MustCompile(`(?m)^\s*image:\s*(\S+)`).FindAllStringSubmatch(readRepositoryFile(t, root, filepath.Join("deploy", "gateway", "docker-compose.yml")), -1)...,
	)
	disclosable := 0
	for _, match := range pinned {
		ref := match[1]
		// The Gateway's own image is built from this repository and carries no
		// upstream digest, so only third-party base images are disclosures.
		if !strings.Contains(ref, "@sha256:") {
			continue
		}
		disclosable++
		if !noticesDisclose(notices, ref) {
			t.Fatalf("THIRD_PARTY_NOTICES does not disclose the pinned image %q: it names an image the deployment no longer uses", ref)
		}
	}
	if disclosable < 3 {
		t.Fatalf("found %d digest-pinned upstream images in the Gateway deployment, expected at least 3 (Go build, runtime base, edge proxy)", disclosable)
	}
}

// noticesDisclose reports whether the notices file names this exact image tag
// and a digest the real pin starts with. The disclosure truncates digests for
// readability, so a prefix is the strongest true statement it can make — but a
// stale tag or a digested bump that no longer matches fails, which is the drift
// this gate exists to catch.
func noticesDisclose(notices, ref string) bool {
	at := strings.Index(ref, "@sha256:")
	if at < 0 {
		return false
	}
	nameTag, digest := ref[:at], ref[at+len("@sha256:"):]
	for _, disclosed := range disclosedImageRef.FindAllString(notices, -1) {
		disclosedAt := strings.Index(disclosed, "@sha256:")
		if disclosedAt < 0 || disclosed[:disclosedAt] != nameTag {
			continue
		}
		if strings.HasPrefix(digest, disclosed[disclosedAt+len("@sha256:"):]) {
			return true
		}
	}
	return false
}

func readRepositoryFile(t *testing.T, root string, parts ...string) string {
	t.Helper()

	path := filepath.Join(append([]string{root}, parts...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
