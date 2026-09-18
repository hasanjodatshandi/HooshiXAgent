package architecture_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Windows Agent delivery documentation guard.
//
// ADR-0010 chose a user-scoped Windows Agent (per-user binary plus a logon
// Scheduled Task). The Windows distribution that was actually built and
// deployed implements the LocalSystem service model instead, while every
// current document kept describing the user-scoped model as if it were the
// decision. ADR-0014 records the service model as accepted and supersedes the
// Windows clauses of ADR-0010.
//
// This guard exists so the two cannot silently diverge again. It fails when:
//
//   - a current (non-ADR) document states the superseded user-scoped model as
//     the model in force, rather than describing it as superseded;
//   - one of the documents that describes the Windows delivery model stops
//     referencing the accepted ADR;
//   - the accepted ADR is missing or is no longer `Accepted`;
//   - the register stops recording ADR-0014 or the ADR-0010 supersession;
//   - ADR-0010's historical body is rewritten to match the new decision
//     instead of carrying a supersession pointer (governance section 2).
//
// It deliberately does not treat every mention of the superseded model as a
// violation: the disclosure of the not-yet-aligned archive installer is
// required to be truthful and must stay possible. It rejects the specific
// assertions that presented that model as current.
const (
	acceptedWindowsDeliveryADR       = "ADR-0014"
	acceptedWindowsDeliveryADRPath   = "docs/adr/ADR-0014-windows-agent-service-persistence-and-secret-trust.md"
	supersededWindowsDeliveryADRPath = "docs/adr/ADR-0010-packaging-deployment-and-release-trust.md"
	decisionRegisterPath             = "docs/adr/decision-register.md"
)

// windowsDeliveryDocuments are the current documents that describe the Windows
// Agent delivery model. Each must reference the accepted ADR. Adding or
// removing an entry here is a deliberate documentation-contract change.
var windowsDeliveryDocuments = []string{
	"README.md",
	"packaging/agent/README.md",
	"docs/runtime/agent.md",
	"docs/runtime/packaging-and-operations.md",
	"docs/runtime/security-resilience-release-gate.md",
	"docs/engineering/current-state.md",
	"docs/engineering/executable-runtime-gate.md",
}

// supersededWindowsDeliveryClaims are statements that present the superseded
// user-scoped Windows model as the model in force. Each must not reappear in
// any windowsDeliveryDocuments entry.
var supersededWindowsDeliveryClaims = []string{
	"Windows deliberately does not install a LocalSystem service",
	"Windows uses a current-user logon Scheduled Task so DPAPI CurrentUser ownership remains intact",
	"Windows: current-user logon Scheduled Task",
	"This is intentional: Windows Agent secrets use DPAPI CurrentUser and Unix Agent state is per-user.",
	"AG-7 does not change that trust boundary.",
	"Default persistence is user-scoped",
	"The installer is user-scoped by default so the running Agent remains under the same OS user",
	"The supported, released Windows artifact is",
	"native user-scoped persistence definitions",
}

// adr0010HistoricalWindowsClause is ADR-0010's rejected-alternative entry for
// the service model. It must survive verbatim: superseding a decision is a
// pointer operation, not a rewrite of the record that was superseded.
const adr0010HistoricalWindowsClause = "- Machine-scope Windows DPAPI plus LocalSystem service: rejected because it weakens/changes the accepted secret trust boundary."

func TestWindowsAgentDeliveryDocumentationMatchesAcceptedADR(t *testing.T) {
	t.Parallel()

	violations, err := collectWindowsDeliveryViolations(repositoryRoot(t))
	if err != nil {
		t.Fatalf("windows delivery documentation guard failed: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("Windows Agent delivery documentation/ADR divergence:\n- %s", strings.Join(violations, "\n- "))
	}
}

func TestWindowsDeliveryGuardRejectsSupersededClaim(t *testing.T) {
	t.Parallel()

	root := newWindowsDeliveryFixture(t)
	mustWriteFile(t, filepath.Join(root, "README.md"),
		"Agent persistence per ADR-0014.\n\nWindows deliberately does not install a LocalSystem service because Agent secret state is protected with DPAPI CurrentUser.\n")

	violations, err := collectWindowsDeliveryViolations(root)
	if err != nil {
		t.Fatalf("guard failed: %v", err)
	}
	assertViolationContains(t, violations, "superseded Windows model stated as current")
}

func TestWindowsDeliveryGuardRejectsMissingAcceptedADRReference(t *testing.T) {
	t.Parallel()

	root := newWindowsDeliveryFixture(t)
	mustWriteFile(t, filepath.Join(root, "docs", "runtime", "agent.md"),
		"Windows Agent persistence documentation that never names the decision it implements.\n")

	violations, err := collectWindowsDeliveryViolations(root)
	if err != nil {
		t.Fatalf("guard failed: %v", err)
	}
	assertViolationContains(t, violations, "does not reference "+acceptedWindowsDeliveryADR)
}

func TestWindowsDeliveryGuardRejectsUnacceptedADR(t *testing.T) {
	t.Parallel()

	root := newWindowsDeliveryFixture(t)
	mustWriteFile(t, filepath.Join(root, filepath.FromSlash(acceptedWindowsDeliveryADRPath)),
		"# ADR-0014: Windows Agent Persistence\n\nStatus: Proposed\nDate: 2026-09-16\n")

	violations, err := collectWindowsDeliveryViolations(root)
	if err != nil {
		t.Fatalf("guard failed: %v", err)
	}
	assertViolationContains(t, violations, "is not `Status: Accepted`")
}

func TestWindowsDeliveryGuardRejectsMissingSupersessionRecord(t *testing.T) {
	t.Parallel()

	root := newWindowsDeliveryFixture(t)
	mustWriteFile(t, filepath.Join(root, filepath.FromSlash(decisionRegisterPath)),
		"# HooshiXAgent ADR Decision Register\n\n| ID | Title | Status | Date | Current authority | Supersedes | Superseded by | File |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n| ADR-0010 | Agent Packaging, Gateway Deployment and Release Trust | Accepted | 2026-08-29 | Yes | — | — | `docs/adr/ADR-0010-packaging-deployment-and-release-trust.md` |\n")

	violations, err := collectWindowsDeliveryViolations(root)
	if err != nil {
		t.Fatalf("guard failed: %v", err)
	}
	assertViolationContains(t, violations, "register does not record")
}

func TestWindowsDeliveryGuardRejectsRewrittenSupersededADRHistory(t *testing.T) {
	t.Parallel()

	root := newWindowsDeliveryFixture(t)
	mustWriteFile(t, filepath.Join(root, filepath.FromSlash(supersededWindowsDeliveryADRPath)),
		"# ADR-0010: Agent Packaging, Gateway Deployment and Release Trust\n\nStatus: Accepted\nDate: 2026-08-29\n\nSuperseded in part by ADR-0014.\n\n## Alternatives\n\n- Nothing to see here.\n")

	violations, err := collectWindowsDeliveryViolations(root)
	if err != nil {
		t.Fatalf("guard failed: %v", err)
	}
	assertViolationContains(t, violations, "historical decision record was rewritten")
}

// collectWindowsDeliveryViolations returns every Windows delivery
// documentation/authority divergence found under root.
func collectWindowsDeliveryViolations(root string) ([]string, error) {
	var violations []string

	for _, document := range windowsDeliveryDocuments {
		text, err := readRepoText(root, document)
		if err != nil {
			violations = append(violations, err.Error())
			continue
		}
		for _, claim := range supersededWindowsDeliveryClaims {
			if strings.Contains(text, claim) {
				violations = append(violations, "superseded Windows model stated as current: "+document+" asserts "+quoteClaim(claim))
			}
		}
		if !strings.Contains(text, acceptedWindowsDeliveryADR) {
			violations = append(violations, "current Windows delivery document does not reference "+acceptedWindowsDeliveryADR+": "+document)
		}
	}

	acceptedADR, err := readRepoText(root, acceptedWindowsDeliveryADRPath)
	if err != nil {
		violations = append(violations, err.Error())
	} else if !hasExactLine(acceptedADR, "Status: Accepted") {
		violations = append(violations, acceptedWindowsDeliveryADRPath+" is not `Status: Accepted`, so it is not current Windows delivery authority")
	}

	supersededADR, err := readRepoText(root, supersededWindowsDeliveryADRPath)
	if err != nil {
		violations = append(violations, err.Error())
	} else {
		if !strings.Contains(supersededADR, acceptedWindowsDeliveryADR) {
			violations = append(violations, supersededWindowsDeliveryADRPath+" carries no supersession pointer to "+acceptedWindowsDeliveryADR)
		}
		if !strings.Contains(supersededADR, adr0010HistoricalWindowsClause) {
			violations = append(violations, "historical decision record was rewritten: "+supersededWindowsDeliveryADRPath+" no longer contains its original rejected-alternative entry")
		}
	}

	register, err := readRepoText(root, decisionRegisterPath)
	if err != nil {
		violations = append(violations, err.Error())
	} else {
		if !strings.Contains(register, "| "+acceptedWindowsDeliveryADR+" ") || !strings.Contains(register, "| Accepted |") {
			violations = append(violations, "register does not record "+acceptedWindowsDeliveryADR+" as Accepted: "+decisionRegisterPath)
		}
		if !registerRowMentions(register, "ADR-0010", acceptedWindowsDeliveryADR) {
			violations = append(violations, "register does not record that "+acceptedWindowsDeliveryADR+" supersedes "+"ADR-0010 Windows clauses: "+decisionRegisterPath)
		}
	}

	return violations, nil
}

func readRepoText(root, relSlash string) (string, error) {
	path := filepath.Join(root, filepath.FromSlash(relSlash))
	data, err := os.ReadFile(path)
	if err != nil {
		return "", &windowsDeliveryFileError{rel: relSlash, err: err}
	}
	return string(data), nil
}

type windowsDeliveryFileError struct {
	rel string
	err error
}

func (e *windowsDeliveryFileError) Error() string {
	return "required Windows delivery authority file is unreadable: " + e.rel
}

func (e *windowsDeliveryFileError) Unwrap() error { return e.err }

// hasExactLine reports whether any line, ignoring surrounding whitespace, is
// exactly want. The ADR status field is a whole line, not a prose mention.
func hasExactLine(text, want string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// registerRowMentions reports whether the register table row for id also
// mentions other. Supersession is recorded in that row's columns.
func registerRowMentions(register, id, other string) bool {
	for _, line := range strings.Split(register, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "| "+id+" ") {
			continue
		}
		if strings.Contains(trimmed, other) {
			return true
		}
	}
	return false
}

func quoteClaim(claim string) string {
	if len(claim) <= 60 {
		return "`" + claim + "`"
	}
	return "`" + claim[:57] + "...`"
}

// newWindowsDeliveryFixture builds a minimal synthetic repository that
// satisfies the guard, so a negative test can mutate exactly one fact and prove
// the guard fires on it.
func newWindowsDeliveryFixture(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, filepath.FromSlash(acceptedWindowsDeliveryADRPath)),
		"# ADR-0014: Windows Agent Persistence and Secret Trust Model (LocalSystem Service)\n\nStatus: Accepted\nDate: 2026-09-16\n")
	mustWriteFile(t, filepath.Join(root, filepath.FromSlash(supersededWindowsDeliveryADRPath)),
		"# ADR-0010: Agent Packaging, Gateway Deployment and Release Trust\n\nStatus: Accepted\nDate: 2026-08-29\n\nSuperseded in part by ADR-0014.\n\n## Alternatives\n\n"+adr0010HistoricalWindowsClause+"\n")
	mustWriteFile(t, filepath.Join(root, filepath.FromSlash(decisionRegisterPath)),
		"# HooshiXAgent ADR Decision Register\n\n| ID | Title | Status | Date | Current authority | Supersedes | Superseded by | File |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n| ADR-0010 | Agent Packaging, Gateway Deployment and Release Trust | Accepted | 2026-08-29 | Yes — except the clauses listed in ADR-0014 | — | ADR-0014 — Windows Agent persistence/secret trust clauses only | `docs/adr/ADR-0010-packaging-deployment-and-release-trust.md` |\n| ADR-0014 | Windows Agent Persistence and Secret Trust Model (LocalSystem Service) | Accepted | 2026-09-16 | Yes | ADR-0010 — Windows Agent persistence/secret trust clauses only | — | `"+acceptedWindowsDeliveryADRPath+"` |\n")
	for _, document := range windowsDeliveryDocuments {
		mustWriteFile(t, filepath.Join(root, filepath.FromSlash(document)),
			"Windows Agent persistence follows the accepted service model in "+acceptedWindowsDeliveryADR+".\n")
	}
	return root
}
