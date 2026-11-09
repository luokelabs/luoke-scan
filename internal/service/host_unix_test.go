package service

import "golang.org/x/sys/unix"

func sysSocketpair() ([2]int, error) { return unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0) }
