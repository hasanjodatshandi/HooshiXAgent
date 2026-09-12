package svc

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// applyRecoveryPolicy configures "restart on failure" via ChangeServiceConfig2
// (SERVICE_CONFIG_FAILURE_ACTIONS): restart after 5s, reset the failure
// counter after one day. Combined with the supervisor's internal reconnect
// loop, the service self-heals from crashes and network outages.
func applyRecoveryPolicy(handle windows.Handle) error {
	type scAction struct {
		actionType uint32
		delayMs    uint32
	}
	type failureActions struct {
		resetPeriodDays uint32
		rebootMsg       *uint16
		command         *uint16
		actionsCount    uint32
		actions         *scAction
	}
	const (
		scActionRestart       = 1
		serviceConfigFailures = 2
	)
	actions := []scAction{{actionType: scActionRestart, delayMs: 5000}}
	fa := failureActions{
		resetPeriodDays: 1,
		actionsCount:    uint32(len(actions)),
		actions:         &actions[0],
	}
	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	changeServiceConfig2 := advapi32.NewProc("ChangeServiceConfig2W")
	result, _, err := changeServiceConfig2.Call(
		uintptr(handle),
		uintptr(serviceConfigFailures),
		uintptr(unsafe.Pointer(&fa)),
	)
	if result == 0 {
		return fmt.Errorf("ChangeServiceConfig2: %w", err)
	}
	return nil
}

// grantUserStartStop replaces the service DACL with one that keeps the
// standard defaults but additionally allows interactive users (IU) the
// minimal tray rights: query status, start, stop, interrogate. Configuration
// changes (delete/config) stay administrator-only.
func grantUserStartStop(handle windows.Handle) error {
	// SDDL: allow SYSTEM and Administrators full control, and interactive
	// users the tray subset (LCSWLOCRRC = list/read + start + stop + interrogate).
	const sddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LCSWLOCRRC;;;IU)"
	security, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse service SDDL: %w", err)
	}
	const daclSecurityInformation = 0x00000004
	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	setServiceObjectSecurity := advapi32.NewProc("SetServiceObjectSecurity")
	result, _, err := setServiceObjectSecurity.Call(
		uintptr(handle),
		uintptr(daclSecurityInformation),
		uintptr(unsafe.Pointer(security)),
	)
	if result == 0 {
		return fmt.Errorf("SetServiceObjectSecurity: %w", err)
	}
	return nil
}
