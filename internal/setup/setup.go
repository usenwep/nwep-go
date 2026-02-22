//go:build ignore

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func main() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-File", "setup.ps1")
	} else {
		cmd = exec.Command("bash", "setup.sh")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "setup failed: %v\n", err)
		os.Exit(1)
	}
}
