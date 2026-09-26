package main

import (
	"os/exec"
	"syscall"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/config"
)

func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

func loadConfigFile(path string) error { return config.LoadFile(path) }

func loadConfig() (*config.Config, error) { return config.Load() }
