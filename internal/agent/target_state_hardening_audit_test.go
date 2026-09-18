package agent

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestValidateLocalTargetGrammar pins the accepted local-target grammar,
// including the ASCII-only localhost match: "localho\u017f" (U+017F) must be
// rejected even though strings.EqualFold accepted it.
func TestValidateLocalTargetGrammar(t *testing.T) {
	accepted := []string{
		"localhost:80",
		"LOCALHOST:8080",
		"LocalHost:443",
		"127.0.0.1:8080",
		"127.0.0.2:1",
		"127.255.255.254:65535",
		"[::1]:8080",
	}
	for _, target := range accepted {
		if err := ValidateLocalTarget(target); err != nil {
			t.Errorf("ValidateLocalTarget(%q)=%v want nil", target, err)
		}
	}
	rejected := []string{
		"localho\u017ft:8080",
		"\u0130ocalhost:8080",
		"localhost",
		"localhost:",
		"localhost:0",
		"localhost:65536",
		"localhost:-1",
		"example.com:80",
		"10.0.0.1:80",
		"169.254.169.254:80",
		"0.0.0.0:80",
		"127.0.0.1.attacker.example:80",
		"tcp://127.0.0.1:80",
		"127.0.0.1:80/path",
		"127.0.0.1:80?x=1",
	}
	for _, target := range rejected {
		if err := ValidateLocalTarget(target); err == nil {
			t.Errorf("ValidateLocalTarget(%q) was accepted", target)
		}
	}
}

// TestDialLocalTargetDiallsOnlyLoopback proves the DIAL path (not just the
// validator) only ever reaches a loopback address, for both the literal and the
// localhost spellings.
func TestDialLocalTargetDiallsOnlyLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted <- struct{}{}
			conn.Close()
		}
	}()

	for _, target := range []string{"127.0.0.1:" + strconv.Itoa(port), "localhost:" + strconv.Itoa(port), "LOCALHOST:" + strconv.Itoa(port)} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, dialErr := DialLocalTarget(ctx, target, 2*time.Second)
		cancel()
		if dialErr != nil {
			t.Fatalf("DialLocalTarget(%q)=%v", target, dialErr)
		}
		remote, _, splitErr := net.SplitHostPort(conn.RemoteAddr().String())
		if splitErr != nil {
			t.Fatalf("remote address of %q: %v", target, splitErr)
		}
		ip := net.ParseIP(remote)
		if ip == nil || !ip.IsLoopback() {
			t.Fatalf("DialLocalTarget(%q) reached non-loopback %s", target, remote)
		}
		conn.Close()
	}

	// All three successful dials are counted before the negative case, so the
	// baseline cannot be raised by a late accept from the loop above.
	for index := 0; index < 3; index++ {
		select {
		case <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of 3 loopback dials were accepted", index)
		}
	}

	// A rejected target must never even attempt a connection.
	before := len(accepted)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, dialErr := DialLocalTarget(ctx, "example.com:80", time.Second); dialErr == nil {
		conn.Close()
		t.Fatal("DialLocalTarget connected to a non-loopback host")
	}
	time.Sleep(200 * time.Millisecond)
	if after := len(accepted); after != before {
		t.Fatalf("a rejected target still opened %d connection(s)", after-before)
	}
}

// TestEnsurePairingCapabilityNeverRotatesOnFailure proves an existing
// capability is returned unchanged and a broken/missing one is either reported
// (broken) or created (missing). The previous implementation regenerated and
// overwrote the file on ANY read error, silently invalidating the URL an
// operator had already been given.
func TestEnsurePairingCapabilityNeverRotatesOnFailure(t *testing.T) {
	dir := t.TempDir()

	// Missing: created exactly once, then stable.
	first, err := EnsurePairingCapability(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 43 {
		t.Fatalf("generated capability %q is not 256 bits of base64url", first)
	}
	second, err := EnsurePairingCapability(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("an existing capability was rotated: %q -> %q", first, second)
	}

	// Present but unreadable/invalid: reported, NOT overwritten.
	path := PairingCapabilityPath(dir)
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsurePairingCapability(dir); err == nil {
		t.Fatal("a corrupt capability file was silently replaced")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "short" {
		t.Fatalf("a corrupt capability file was overwritten: %q", contents)
	}

	// An unreadable path (a directory) is reported, not replaced.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsurePairingCapability(dir); err == nil {
		t.Fatal("an unreadable capability path was silently replaced")
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatalf("the capability path was replaced: %v %v", info, err)
	}

	// WritePairingCapability still rejects a malformed value.
	if err := WritePairingCapability(dir, "too-short"); err == nil {
		t.Fatal("WritePairingCapability accepted a malformed capability")
	}
	if _, err := LoadPairingEndpoint(dir); err == nil {
		t.Fatal("LoadPairingEndpoint accepted a missing record")
	}
}

// TestPairingEndpointRecordValidation proves the published listener record is
// validated on read: a malformed port or token is an error, and the record
// round-trips byte-for-byte.
func TestPairingEndpointRecordValidation(t *testing.T) {
	dir := t.TempDir()
	want := PairingEndpoint{
		Port:      8799,
		Token:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		PID:       4242,
		CreatedAt: "2026-09-16T00:00:00Z",
	}
	if err := WritePairingEndpoint(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPairingEndpoint(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip: got %+v want %+v", got, want)
	}
	if err := RemovePairingEndpoint(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPairingEndpoint(dir); err == nil {
		t.Fatal("the removed record still loaded")
	}
	// Removing twice is not an error (idempotent shutdown).
	if err := RemovePairingEndpoint(dir); err != nil {
		t.Fatalf("second remove: %v", err)
	}

	for name, record := range map[string]string{
		"port zero":       `{"port":0,"token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","pid":1,"created_at":"x"}`,
		"port too large":  `{"port":70000,"token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","pid":1,"created_at":"x"}`,
		"token too short": `{"port":8799,"token":"short","pid":1,"created_at":"x"}`,
		"not json":        `{`,
	} {
		if err := os.WriteFile(filepath.Join(dir, "pairing.endpoint.json"), []byte(record), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPairingEndpoint(dir); err == nil {
			t.Errorf("%s: malformed record was accepted", name)
		}
	}
}
