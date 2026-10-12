package connectgui

import (
	"strings"
	"testing"
)

func TestButtonsFor(t *testing.T) {
	cases := []struct {
		name          string
		status        Status
		disconnecting bool
		want          Buttons
	}{
		{
			name:   "idle offers only connect",
			status: Status{State: StateIdle},
			want:   Buttons{Connect: true},
		},
		{
			name:   "tcp session offers disconnect and remote desktop",
			status: Status{State: StateListening, Protocol: "tcp", Listen: "127.0.0.1:13389"},
			want:   Buttons{Disconnect: true, OpenClient: true},
		},
		{
			name:   "udp session cannot offer remote desktop",
			status: Status{State: StateListening, Protocol: "udp", Listen: "127.0.0.1:13400"},
			want:   Buttons{Disconnect: true},
		},
		{
			name:   "a second client would steal the one interactive session",
			status: Status{State: StateListening, Protocol: "tcp", Listen: "127.0.0.1:13389", Flows: 1},
			want:   Buttons{Disconnect: true},
		},
		{
			name:   "several attached clients still allow only disconnect",
			status: Status{State: StateListening, Protocol: "tcp", Listen: "127.0.0.1:13389", Flows: 3},
			want:   Buttons{Disconnect: true},
		},
		{
			name:   "a detached client frees the button again",
			status: Status{State: StateListening, Protocol: "tcp", Listen: "127.0.0.1:13389", Flows: 0},
			want:   Buttons{Disconnect: true, OpenClient: true},
		},
		{
			name:   "a failed session can be retried",
			status: Status{State: StateFailed, Protocol: "tcp"},
			want:   Buttons{Connect: true},
		},
		{
			name:   "a closed session can be reopened",
			status: Status{State: StateStopped, Protocol: "tcp"},
			want:   Buttons{Connect: true},
		},
		{
			name:          "teardown disables everything",
			status:        Status{State: StateListening, Protocol: "tcp", Listen: "127.0.0.1:13389"},
			disconnecting: true,
			want:          Buttons{},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ButtonsFor(testCase.status, testCase.disconnecting); got != testCase.want {
				t.Fatalf("ButtonsFor() = %+v, want %+v", got, testCase.want)
			}
		})
	}
}

func TestStatusLabel(t *testing.T) {
	if got := StatusLabel(Status{State: StateListening, Protocol: "tcp", Listen: "127.0.0.1:13389"}, false); got != "listening on 127.0.0.1:13389 (tcp)" {
		t.Fatalf("listening label = %q", got)
	}
	if got := StatusLabel(Status{State: StateListening, Protocol: "tcp"}, true); got != "disconnecting" {
		t.Fatalf("disconnecting label = %q", got)
	}
	if got := StatusLabel(Status{State: StateIdle}, false); got != "idle" {
		t.Fatalf("idle label = %q", got)
	}
}

// TestIdleMessageMatchesTheWindowThatShowsIt pins the sentence that made the
// saved-bundle window tell the operator to paste a bundle it had hidden.
func TestIdleMessageMatchesTheWindowThatShowsIt(t *testing.T) {
	saved := IdleMessage(true)
	if strings.Contains(saved, "paste") {
		t.Errorf("the window with no paste area still asks for one: %q", saved)
	}
	if !strings.Contains(IdleMessage(false), "paste") {
		t.Errorf("the first-run window does not say what to do: %q", IdleMessage(false))
	}
	if saved == IdleMessage(false) {
		t.Error("both shapes give the same instruction")
	}
	if !strings.Contains(saved, "Connect") {
		t.Errorf("the saved-bundle instruction does not name the button to press: %q", saved)
	}
}

func TestRDPTarget(t *testing.T) {
	cases := []struct {
		name    string
		status  Status
		want    string
		wantErr bool
	}{
		{name: "ipv4 session", status: Status{State: StateListening, Protocol: "tcp", Listen: "127.0.0.1:13389"}, want: "127.0.0.1:13389"},
		{name: "loopback range", status: Status{State: StateListening, Protocol: "tcp", Listen: "127.5.6.7:3389"}, want: "127.5.6.7:3389"},
		{name: "ipv6 session is bracketed", status: Status{State: StateListening, Protocol: "tcp", Listen: "[::1]:3389"}, want: "[::1]:3389"},
		{name: "not listening", status: Status{State: StateStopped, Protocol: "tcp", Listen: "127.0.0.1:3389"}, wantErr: true},
		{name: "udp has no remote desktop", status: Status{State: StateListening, Protocol: "udp", Listen: "127.0.0.1:3389"}, wantErr: true},
		{name: "non-loopback is refused", status: Status{State: StateListening, Protocol: "tcp", Listen: "203.0.113.7:3389"}, wantErr: true},
		{name: "hostname is refused", status: Status{State: StateListening, Protocol: "tcp", Listen: "localhost:3389"}, wantErr: true},
		{name: "missing port is refused", status: Status{State: StateListening, Protocol: "tcp", Listen: "127.0.0.1"}, wantErr: true},
		{name: "empty address is refused", status: Status{State: StateListening, Protocol: "tcp"}, wantErr: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := RDPTarget(testCase.status)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("RDPTarget(%q) = %q, want an error", testCase.status.Listen, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("RDPTarget: %v", err)
			}
			if got != testCase.want {
				t.Fatalf("RDPTarget() = %q, want %q", got, testCase.want)
			}
		})
	}
}
