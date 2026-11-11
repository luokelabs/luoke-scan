//go:build !darwin

package service

import "os/exec"

// FromApp: only macOS has an installed 螺壳 to check against (fromapp_darwin.go).
func FromApp(allowSelf bool) string { return "" }

func startVouched(cmd *exec.Cmd) bool { return cmd.Start() == nil }
