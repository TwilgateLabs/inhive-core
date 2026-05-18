package main

import (
	"os"

	"github.com/twilgate/inhive-core/cmd"
)

func main() {
	cmd.ParseCli(os.Args[1:])
}
