//go:build windows

package main

import (
	"path/filepath"
	"testing"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/connectgui"
)

// TestRemoteDesktopLaunchIsVisible pins the defect the operator experienced as
// "the button did nothing": mstsc started with SW_HIDE connects but never shows a
// window, taskbar button or Alt+Tab entry.
func TestRemoteDesktopLaunchIsVisible(t *testing.T) {
	spec := newRemoteDesktopSpec(`C:\Windows`, "127.0.0.1:13389")
	if spec.sysProcAttr != nil && spec.sysProcAttr.HideWindow {
		t.Fatalf("mstsc would start hidden: %#v", spec.sysProcAttr)
	}
	if want := filepath.Join(`C:\Windows`, "System32", "mstsc.exe"); spec.path != want {
		t.Errorf("path = %q, want %q", spec.path, want)
	}
	if len(spec.args) != 1 || spec.args[0] != "/v:127.0.0.1:13389" {
		t.Errorf("args = %q, want one /v: target", spec.args)
	}
}

// TestLaunchBundleReusesTheClearedCredential proves the connect button still
// works after the edit control has been emptied for the operator's sake.
func TestLaunchBundleReusesTheClearedCredential(t *testing.T) {
	if got, err := launchBundle("hx1.pasted", "hx1.remembered"); err != nil || got != "hx1.pasted" {
		t.Errorf("launchBundle(pasted) = %q, %v", got, err)
	}
	if got, err := launchBundle("", "hx1.remembered"); err != nil || got != "hx1.remembered" {
		t.Errorf("launchBundle(cleared edit) = %q, %v", got, err)
	}
	if got, err := launchBundle("", ""); err == nil || got != "" {
		t.Errorf("launchBundle(nothing) = %q, %v, want an error", got, err)
	} else if err.Error() != "paste the connect bundle the Panel issued first" {
		// A windowsgui binary has no console: a refused Connect that says nothing
		// is indistinguishable from a hung button.
		t.Errorf("unexpected refusal: %v", err)
	}
}

// TestHintWarnsAboutTheSecondClient keeps the on-screen rule that matches the
// button policy rendered by ButtonsFor.
func TestHintWarnsAboutTheSecondClient(t *testing.T) {
	var hint spec
	for _, candidate := range specs() {
		if candidate.id == idHint {
			hint = candidate
		}
	}
	if hint.title == "" {
		t.Fatal("the window has no hint to explain the button policy")
	}
	status := connectgui.Status{State: connectgui.StateListening, Listen: "127.0.0.1:13389", Protocol: "tcp", Flows: 1}
	if connectgui.ButtonsFor(status, false).OpenClient {
		t.Error("an attached client must disable the button the hint warns about")
	}
}

// TestTheWindowFitsItsText guards the layout that made the hint unreadable: the
// last control must stay inside the client area.
func TestTheWindowFitsItsText(t *testing.T) {
	last := specs()[len(specs())-1]
	if bottom := last.y + last.height; bottom > clientHeight {
		t.Errorf("control %d ends at %d, past the client area %d", last.id, bottom, clientHeight)
	}
}
