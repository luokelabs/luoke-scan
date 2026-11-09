package service

import "os"

func realHome() string {
	h, _ := os.UserHomeDir()
	return h
}
