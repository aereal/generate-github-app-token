package main

import (
	"os"

	generatetoken "github.com/aereal/generate-github-app-token"
)

func main() {
	os.Exit(generatetoken.NewGenerator(os.Stdout, os.Stderr).Run(os.Args))
}
