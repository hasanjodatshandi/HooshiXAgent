package main

import (
	"os"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

func main() {
	os.Exit(agent.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
