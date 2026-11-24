package main

import (
	"fmt"
	"os"
)

func main() {
	if err := execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "endpoint-hunter:", err)
		os.Exit(1)
	}
}
