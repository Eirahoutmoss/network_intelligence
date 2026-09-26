//go:build !windows

package main

func platformCommand(string, []string) (bool, error) { return false, nil }

func serviceRunning() (bool, error) { return false, nil }
