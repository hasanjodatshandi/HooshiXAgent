//go:build windows

package main

import (
	"errors"
	"path/filepath"
	"strings"
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
// button policy rendered by ButtonsFor, in both window shapes: the compact shape
// swaps the hint text but must not drop the warning.
func TestHintWarnsAboutTheSecondClient(t *testing.T) {
	for _, compact := range []bool{false, true} {
		hint := hintText(compact)
		if !strings.Contains(hint, "steals the session") {
			t.Errorf("compact=%v: the hint stopped warning about the second client: %q", compact, hint)
		}
	}
	status := connectgui.Status{State: connectgui.StateListening, Listen: "127.0.0.1:13389", Protocol: "tcp", Flows: 1}
	if connectgui.ButtonsFor(status, false).OpenClient {
		t.Error("an attached client must disable the button the hint warns about")
	}
}

// TestCompactHintExplainsTheSavedBundle covers the operator's new question: a
// window with no paste area has to say where the credential came from and how to
// change or forget it.
func TestCompactHintExplainsTheSavedBundle(t *testing.T) {
	hint := hintText(true)
	for _, want := range []string{connectgui.BundleFileName, "another bundle"} {
		if !strings.Contains(hint, want) {
			t.Errorf("the compact hint never mentions %q: %q", want, hint)
		}
	}
	if strings.Contains(hintText(false), connectgui.BundleFileName) {
		t.Error("the paste-area shape talks about a file the operator has not created yet")
	}
}

// TestOnlyOneShapeShowsThePasteArea pins the requested behaviour: a saved bundle
// removes the code input, and nothing else.
func TestOnlyOneShapeShowsThePasteArea(t *testing.T) {
	for _, shape := range []struct {
		compact    bool
		inPaste    []int
		notInPaste []int
	}{
		{compact: false, inPaste: []int{idBundleCaption, idBundle}, notInPaste: []int{idRevealBundle}},
		{compact: true, inPaste: []int{idRevealBundle}, notInPaste: []int{idBundleCaption, idBundle}},
	} {
		shown := map[int]bool{}
		for _, control := range specs(shape.compact) {
			if control.visible {
				shown[control.id] = true
			}
		}
		for _, id := range shape.inPaste {
			if !shown[id] {
				t.Errorf("compact=%v: control %d should be on screen", shape.compact, id)
			}
		}
		for _, id := range shape.notInPaste {
			if shown[id] {
				t.Errorf("compact=%v: control %d should be hidden", shape.compact, id)
			}
		}
	}
	// Both shapes are drawn from the same control set, so switching shapes never
	// has to create a window control that does not already exist.
	full := specs(false)
	if len(full) != len(specs(true)) {
		t.Fatalf("the two shapes hold %d and %d controls, applyLayout could not swap them", len(full), len(specs(true)))
	}
}

// TestTheWindowFitsItsText guards the layout that made the hint unreadable: the
// last control must stay inside the client area, in both shapes.
func TestTheWindowFitsItsText(t *testing.T) {
	for _, compact := range []bool{false, true} {
		controls := specs(compact)
		last := controls[len(controls)-1]
		if bottom := last.y + last.height; bottom > clientHeightFor(compact) {
			t.Errorf("compact=%v: control %d ends at %d, past the client area %d",
				compact, last.id, bottom, clientHeightFor(compact))
		}
	}
	if clientHeightFor(true) >= clientHeightFor(false) {
		t.Error("the compact shape is not actually shorter, so the frame would keep its old height")
	}
}

// TestHintTextFitsItsStatic is the other half of that guard. The layout test only
// proves the box is inside the window; a STATIC tall enough for the frame can
// still be too short for its own sentence, and the missing words do not overflow,
// shrink or scroll, they are simply not drawn. That is what happened to the
// compact shape's hint: its fourth line lost its lower half. The per-line capacity
// and line height are the ones read off a rendered capture, and the line height is
// rounded up so a larger font scale cannot eat the last row.
func TestHintTextFitsItsStatic(t *testing.T) {
	for _, compact := range []bool{false, true} {
		var hint *spec
		controls := specs(compact)
		for i := range controls {
			if controls[i].id == idHint {
				hint = &controls[i]
			}
		}
		if hint == nil {
			t.Fatalf("compact=%v: the shape has no hint row", compact)
		}
		// Width is authored at 96 DPI, the same basis as the measured capacity.
		if hint.width != clientWidth-32 {
			t.Errorf("compact=%v: the hint is %d DIP wide, the measured wrap was for %d",
				compact, hint.width, clientWidth-32)
		}
		chars := len([]rune(hint.title))
		lines := (chars + hintCharsPerLine - 1) / hintCharsPerLine
		if needed := lines * hintLineHeight; needed > hint.height {
			t.Errorf("compact=%v: the hint needs %d lines (%d characters at %d per line) = %d DIP, its static is %d DIP: %q",
				compact, lines, chars, hintCharsPerLine, needed, hint.height, hint.title)
		}
	}
}

// TestRevealTitleShowsTheSavedDate keeps the button honest about which
// credential the window is holding without printing the whole timestamp.
func TestRevealTitleShowsTheSavedDate(t *testing.T) {
	title := revealSavedTitle("2026-10-12T18:30:00Z")
	if !strings.Contains(title, "2026-10-12") {
		t.Errorf("the title hides the save date: %q", title)
	}
	if strings.Contains(title, "18:30") {
		t.Errorf("the title reads like a record instead of a hint: %q", title)
	}
	if got := revealSavedTitle(""); got != "Use a different bundle" {
		t.Errorf("with nothing saved the title is %q", got)
	}
	if got := revealSavedTitle("yesterday"); got != "Use a different bundle" {
		t.Errorf("an unreadable date must not reach the window: %q", got)
	}
}

// TestIdleLineFitsTheShapeItIsDrawnIn is the runtime defect the saved bundle
// introduced: a window with no paste area must not tell the operator to paste one.
func TestIdleLineFitsTheShapeItIsDrawnIn(t *testing.T) {
	idle := connectgui.Status{State: connectgui.StateIdle}
	if got := messageFor(idle, true); got != connectgui.IdleMessage(true) {
		t.Errorf("compact idle line = %q, want the saved-bundle instruction", got)
	}
	if got := messageFor(idle, false); got != connectgui.IdleMessage(false) {
		t.Errorf("full idle line = %q, want the paste instruction", got)
	}
	// Every other message was written by a session or an action, and the shape has
	// no business rewriting it.
	for _, status := range []connectgui.Status{
		{State: connectgui.StateListening, Message: "tunnel is up"},
		{State: connectgui.StateFailed, Message: "gateway refused the grant"},
		{State: connectgui.StateStopped, Message: "tunnel closed"},
	} {
		if got := messageFor(status, true); got != status.Message {
			t.Errorf("%s message was rewritten to %q", status.State, got)
		}
	}
}

// TestSavedBundleStateChoosesTheShape pins the rule that decides the first paint.
func TestSavedBundleStateChoosesTheShape(t *testing.T) {
	if !(savedBundleState{bundle: "hx1.x"}).compact() {
		t.Error("a run with a saved bundle still showed the paste area")
	}
	if (savedBundleState{}).compact() {
		t.Error("a first run opened without the input it needs")
	}
	// A file this run could not open leaves the paste area up: the operator has to
	// be able to fix it, and the store survives so the next Connect overwrites it.
	if (savedBundleState{problem: errors.New("no")}).compact() {
		t.Error("an unreadable cfg must not hide the input")
	}
}
