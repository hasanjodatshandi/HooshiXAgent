//go:build windows

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
		resetPeriodSeconds uint32
		rebootMsg          *uint16
		command            *uint16
		actionsCount       uint32
		actions            *scAction
	}
	const (
		scActionRestart       = 1
		serviceConfigFailures = 2
	)
	actions := []scAction{{actionType: scActionRestart, delayMs: 5000}}
	fa := failureActions{
		resetPeriodSeconds: 24 * 60 * 60,
		actionsCount:       uint32(len(actions)),
		actions:            &actions[0],
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

// serviceFullControlRights is the access mask SYSTEM and Administrators hold
// on the service object (the SDDL "CCDCLCSWRPWPDTLOCRSDRCWDWO" string).
const serviceFullControlRights = windows.SERVICE_ALL_ACCESS

// interactiveUserServiceRights is exactly what the LeastPrivilege tray task
// needs and nothing more: SERVICE_QUERY_STATUS to render the status row,
// SERVICE_START for "Start service", SERVICE_STOP for "Stop service".
// Interrogate, user-defined control, change-config, delete and DACL writes
// stay unavailable to interactive users.
const interactiveUserServiceRights = windows.SERVICE_QUERY_STATUS | windows.SERVICE_START | windows.SERVICE_STOP

// serviceStartStopSDDL is the service DACL applied by Install. It replaces
// the SCM defaults with one that keeps SYSTEM/Administrators in full control
// while granting interactive users (IU) exactly
// interactiveUserServiceRights. The IU ace was previously "LCSWLOCRRC"
// (LC=list/query-status, SW=enumerate-dependents, LO=interrogate,
// CR=user-defined-control, RC=read-control) which contains NEITHER
// SERVICE_START (RP, 0x10) nor SERVICE_STOP (WP, 0x20) despite the comment
// claiming both, so every tray start/stop failed with access denied.
const serviceStartStopSDDL = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LCRPWP;;;IU)"

// grantUserStartStop replaces the service DACL with one that keeps the
// standard defaults but additionally allows interactive users (IU) the
// minimal tray rights: query status, start, stop. Configuration changes
// (delete/config) stay administrator-only.
func grantUserStartStop(handle windows.Handle) error {
	security, err := windows.SecurityDescriptorFromString(serviceStartStopSDDL)
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
