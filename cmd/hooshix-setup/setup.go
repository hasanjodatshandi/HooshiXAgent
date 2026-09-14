//go:build windows

package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed payload/hooshix-agent.exe payload/hooshix-agent-tray.exe
var payload embed.FS

const (
	installDir      = `C:\Program Files\HooshiXAgent`
	arpKeyPath      = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HooshiXAgent`
	appTitle        = "HooshiX Agent"
	agentBinary     = "hooshix-agent.exe"
	trayBinary      = "hooshix-agent-tray.exe"
	uninstallBinary = "uninstall.exe"
	trayTaskName    = "HooshiXAgentTray"
)

var setupVersion = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "setup failed:", err)
		pause()
		os.Exit(1)
	}
	pause()
}

func run() error {
	fmt.Println("=== HooshiX Agent Setup ===")
	stage, err := stagePayload()
	if err != nil {
		return fmt.Errorf("stage binaries: %w", err)
	}
	defer os.RemoveAll(stage)
	interactiveAccount, err := interactiveUser()
	if err != nil {
		return fmt.Errorf("determine interactive user: %w", err)
	}

	stopPreviousInstallation()
	backups, err := commitStagedPayload(stage)
	if err != nil {
		return fmt.Errorf("install binaries: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			rollbackFiles(backups)
		}
	}()

	if err := installPairingCapability(interactiveAccount); err != nil {
		return fmt.Errorf("install pairing authorization: %w", err)
	}
	if err := runAgentCommand("service", "install"); err != nil {
		return fmt.Errorf("install service: %w", err)
	}
	if err := runAgentCommand("service", "start"); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	// Desktop integration is best-effort: the tunnel (service + binaries) is
	// already installed and running at this point, so a tray-task or
	// uninstall-entry failure must only warn, never roll the install back
	// (rolling back here would remove binaries the running service points
	// at and leave a half-installed machine).
	if err := registerTrayTask(interactiveAccount); err != nil {
		fmt.Println("warning: tray auto-start was not registered:", err)
		fmt.Println("        the HooshiX Agent service is installed and running; start the tray manually or re-run setup.")
	}
	if err := registerUninstall(); err != nil {
		fmt.Println("warning: Windows uninstall entry was not registered:", err)
	}
	for _, backup := range backups {
		_ = os.Remove(backup)
	}
	committed = true
	fmt.Println("done. The HooshiX Agent service and tray are running.")
	return nil
}

func stagePayload() (string, error) {
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(installDir, ".setup-")
	if err != nil {
		return "", err
	}
	for _, name := range []string{agentBinary, trayBinary} {
		data, readErr := payload.ReadFile("payload/" + name)
		if readErr != nil {
			os.RemoveAll(stage)
			return "", readErr
		}
		if writeErr := os.WriteFile(filepath.Join(stage, name), data, 0o755); writeErr != nil {
			os.RemoveAll(stage)
			return "", writeErr
		}
	}
	self, err := os.Executable()
	if err != nil {
		os.RemoveAll(stage)
		return "", err
	}
	data, err := os.ReadFile(self)
	if err != nil {
		os.RemoveAll(stage)
		return "", err
	}
	if err := os.WriteFile(filepath.Join(stage, uninstallBinary), data, 0o755); err != nil {
		os.RemoveAll(stage)
		return "", err
	}
	return stage, nil
}

func commitStagedPayload(stage string) (map[string]string, error) {
	backups := make(map[string]string)
	for _, name := range []string{agentBinary, trayBinary, uninstallBinary} {
		target := filepath.Join(installDir, name)
		backup := target + ".previous"
		_ = os.Remove(backup)
		if _, err := os.Stat(target); err == nil {
			if err := os.Rename(target, backup); err != nil {
				rollbackFiles(backups)
				return nil, err
			}
			backups[target] = backup
		}
		if err := os.Rename(filepath.Join(stage, name), target); err != nil {
			rollbackFiles(backups)
			return nil, err
		}
		if _, existed := backups[target]; !existed {
			backups[target] = ""
		}
	}
	return backups, nil
}

func rollbackFiles(backups map[string]string) {
	for target, backup := range backups {
		_ = os.Remove(target)
		if backup != "" {
			_ = os.Rename(backup, target)
		}
	}
}

func runAgentCommand(args ...string) error {
	output, err := exec.Command(filepath.Join(installDir, agentBinary), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %w: %s", args, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func stopPreviousInstallation() {
	if err := runAgentCommand("service", "stop"); err != nil {
		fmt.Println("note: stopping previous service:", err)
	}
	_ = exec.Command("schtasks.exe", "/End", "/TN", trayTaskName).Run()
	killProcessByName(trayBinary)
	killProcessByName(agentBinary)
	time.Sleep(time.Second)
}

func killProcessByName(name string) { _ = exec.Command("taskkill.exe", "/F", "/IM", name).Run() }

var (
	wtsapi32DLL = windows.NewLazySystemDLL("wtsapi32.dll")
	wtsQuery    = wtsapi32DLL.NewProc("WTSQuerySessionInformationW")
)

const (
	wtsUserName   = 5 // WTSUserName
	wtsDomainName = 7 // WTSDomainName
	wtsActive     = 0 // WTSActive
)

// interactiveUser returns the account owning the active console session (the
// physical desktop user), not the elevated installer account. It prefers the
// active console session, then falls back to enumerating every WTS session
// for any active one with a logged-on user (covers RDS/multi-session hosts
// where WTSGetActiveConsoleSessionId reports the services session). The
// returned errors are static: a nil error is never wrapped.
func interactiveUser() (string, error) {
	if user := querySessionUser(windows.WTSGetActiveConsoleSessionId()); user != "" {
		return user, nil
	}
	if user := firstActiveSessionUser(); user != "" {
		return user, nil
	}
	return "", errors.New("no logged-on desktop user found in any active session")
}

func querySessionUser(sessionID uint32) string {
	if sessionID == 0 || sessionID == ^uint32(0) {
		return ""
	}
	user := querySessionString(sessionID, wtsUserName)
	if user == "" {
		return ""
	}
	domain := querySessionString(sessionID, wtsDomainName)
	if domain != "" {
		return domain + `\` + user
	}
	return user
}

func querySessionString(sessionID uint32, infoClass uintptr) string {
	var buffer *uint16
	var length uint32
	result, _, _ := wtsQuery.Call(0, uintptr(sessionID), infoClass, uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&length)))
	if result == 0 || buffer == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buffer)))
	return windows.UTF16PtrToString(buffer)
}

// firstActiveSessionUser scans every WTS session for an active one with a
// logged-on user. It is the fallback when the active console session cannot
// be resolved (elevated service contexts, disconnected console, RDS).
func firstActiveSessionUser() string {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil || sessions == nil || count == 0 {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	for _, session := range unsafe.Slice(sessions, count) {
		if session.State != wtsActive {
			continue
		}
		if user := querySessionUser(session.SessionID); user != "" {
			return user
		}
	}
	return ""
}

func registerTrayTask(user string) error {
	// Run as the interactive user without storing their password: schtasks
	// only permits /RU with a password or for the current user with /IT.
	// The logon-trigger task under the console user's own account is
	// created via XML to avoid credential prompts.
	userXML := xmlEscape(user)
	commandXML := xmlEscape(filepath.Join(installDir, trayBinary))
	taskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>HooshiX Agent tray auto-start at logon</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>%s</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
    </Exec>
  </Actions>
</Task>`, userXML, commandXML)
	tempXML := filepath.Join(os.Getenv("TEMP"), "hooshix-tray-task.xml")
	if err := writeUTF16LE(tempXML, taskXML); err != nil {
		return err
	}
	defer os.Remove(tempXML)
	// UserId + InteractiveToken in the XML is sufficient. Adding /RU makes
	// schtasks prompt for that user's password even though none is required.
	args := []string{"/Create", "/F", "/TN", trayTaskName, "/XML", tempXML}
	output, err := exec.Command("schtasks.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks create: %w: %s", err, strings.TrimSpace(string(output)))
	}
	output, err = exec.Command("schtasks.exe", "/Run", "/TN", trayTaskName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks run: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func writeUTF16LE(path, value string) error {
	encoded := utf16.Encode([]rune(value))
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, uint16(0xfeff)); err != nil {
		return err
	}
	if err := binary.Write(&data, binary.LittleEndian, encoded); err != nil {
		return err
	}
	return os.WriteFile(path, data.Bytes(), 0o600)
}

func installPairingCapability(user string) error {
	stateDir := filepath.Join(os.Getenv("ProgramData"), "HooshiXAgent")
	if os.Getenv("ProgramData") == "" {
		stateDir = `C:\ProgramData\HooshiXAgent`
	}
	sid, _, _, err := windows.LookupSID("", user)
	if err != nil {
		return fmt.Errorf("resolve interactive user SID: %w", err)
	}
	userSID := "*" + sid.String()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	// Recovery, not just repair: an earlier installation may have left files
	// with a SYSTEM-only DACL (service-created state), where even an elevated
	// administrator holds no WRITE_DAC, so icacls /grant alone fails with
	// "Access is denied". Recapture ownership first (an elevated admin always
	// holds SeTakeOwnershipPrivilege), then /reset replaces every explicit
	// DACL with inheritable ones so the grants below can never fail.
	if _, statErr := os.Stat(stateDir); statErr == nil {
		if err := recaptureStateOwnership(stateDir); err != nil {
			return fmt.Errorf("recover Agent state directory ownership: %w", err)
		}
		// Ownership now grants WRITE_DAC on every child, so replacing each
		// legacy explicit DACL with the inheritable default cannot fail.
		output, err := exec.Command("icacls.exe", stateDir, "/reset", "/T", "/Q").CombinedOutput()
		if err != nil {
			return fmt.Errorf("reset Agent state directory ACL: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	capability, err := agent.GeneratePairingCapability()
	if err != nil {
		return err
	}
	if err := agent.WritePairingCapability(stateDir, capability); err != nil {
		return err
	}
	output, err := exec.Command("icacls.exe", stateDir,
		"/inheritance:r",
		"/grant:r", userSID+":(OI)(CI)(RX)",
		"/grant:r", "*S-1-5-18:(OI)(CI)(F)",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)(F)",
		"/T", "/Q").CombinedOutput()
	if err != nil {
		return fmt.Errorf("secure Agent state directory ACL: %w: %s", err, strings.TrimSpace(string(output)))
	}
	path := agent.PairingCapabilityPath(stateDir)
	output, err = exec.Command("icacls.exe", path,
		"/inheritance:r",
		"/grant:r", userSID+":(R)",
		"/grant:r", "*S-1-5-18:(F)",
		"/grant:r", "*S-1-5-32-544:(F)").CombinedOutput()
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("secure pairing capability ACL: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func xmlEscape(value string) string {
	var escaped strings.Builder
	_ = xml.EscapeText(&escaped, []byte(value))
	return escaped.String()
}

// recaptureStateOwnership makes the elevated installer the owner of every
// file and directory under root. Service-created state may carry a
// SYSTEM-only DACL where icacls /grant fails with "Access is denied" because
// even an administrator holds no WRITE_DAC. An object's owner always holds
// implicit READ_CONTROL and WRITE_DAC, so transferring ownership first makes
// every subsequent icacls repair succeed. Requires the elevated admin token
// privileges SeTakeOwnershipPrivilege and SeRestorePrivilege, which the
// installer enables itself (no locale-dependent takeown /D prompt).
func recaptureStateOwnership(root string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("open process token: %w", err)
	}
	defer token.Close()
	if !token.IsElevated() {
		return errors.New("state ownership recovery requires the elevated installer token")
	}
	for _, privilege := range []string{"SeTakeOwnershipPrivilege", "SeRestorePrivilege"} {
		if err := enableTokenPrivilege(token, privilege); err != nil {
			return fmt.Errorf("enable %s: %w", privilege, err)
		}
	}
	admins, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return fmt.Errorf("resolve Administrators SID: %w", err)
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
			return fmt.Errorf("take ownership of %s: %w", path, err)
		}
		return nil
	})
}

func enableTokenPrivilege(token windows.Token, name string) error {
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil)
}

func registerUninstall() error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, arpKeyPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()
	values := map[string]string{
		"DisplayName": appTitle, "DisplayVersion": setupVersion, "Publisher": "HooshiX",
		"UninstallString": fmt.Sprintf(`"%s" --uninstall`, filepath.Join(installDir, uninstallBinary)),
		"InstallLocation": installDir, "DisplayIcon": filepath.Join(installDir, trayBinary),
	}
	for name, value := range values {
		if err := key.SetStringValue(name, value); err != nil {
			return err
		}
	}
	if err := key.SetDWordValue("NoModify", 1); err != nil {
		return err
	}
	return key.SetDWordValue("NoRepair", 1)
}

func pause() {
	if stdinInfo, err := os.Stdin.Stat(); err == nil && stdinInfo.Mode()&os.ModeCharDevice != 0 {
		fmt.Print("\nPress Enter to exit ...")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
