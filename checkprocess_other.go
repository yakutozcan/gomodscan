//go:build !unix

package main

import "os/exec"

// CommandContext cancels the parent process on non-Unix platforms.
func configureCheckProcess(cmd *exec.Cmd) {}
