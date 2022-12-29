package main

import (
	"fmt"
	"os"

	"github.com/wangchao475/secretone/pkg/secretone"
)

func main() {
	expected := os.Args[1]
	actual := secretone.ClientVersion

	if actual != expected {
		fmt.Fprintf(os.Stderr, "version not as expected: expected %s got %s\n", expected, actual)
		os.Exit(1)
	} else {
		fmt.Println("version as expected")
	}
}
