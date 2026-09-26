//go:build !windows

package main

import "errors"

func platformCommand(string, []string) (bool, error) { return false, nil }

func serviceRunning() (bool, error) { return false, nil }

func diagnosticsGUI(string) error {
	return errors.New("--gui is only available on Windows")
}
