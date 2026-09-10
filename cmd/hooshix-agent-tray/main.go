//go:build windows

package main

import (
	"os"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/tray"
)

func main() {
	if err := tray.Run(); err != nil {
		os.Stderr.WriteString("tray: " + err.Error() + "\n")
		os.Exit(1)
	}
}
