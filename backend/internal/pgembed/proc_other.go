//go:build !windows

package pgembed

import "os/exec"

func hideWindow(*exec.Cmd) {}
