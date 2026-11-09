package core

import (
	"net"
	"os"
	"testing"
)

// This process listening on the loopback address (only loopback in tests) is found, with its port.
func TestListeningSocketsOfThisProcess(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		addr := "127.0.0.1:0"
		if network == "tcp6" {
			addr = "[::1]:0"
		}
		l, err := net.Listen(network, addr)
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		found := false
		for _, s := range ListeningSockets(int32(os.Getpid())) {
			if s.Port == port {
				found = true
				want := "127.0.0.1"
				if network == "tcp6" {
					want = "::1"
				}
				if s.Address != want || s.Everywhere() {
					t.Fatalf("%s: got %+v", network, s)
				}
			}
		}
		l.Close()
		if !found {
			t.Fatalf("%s: port %d not found", network, port)
		}
	}
}

func TestNtop6(t *testing.T) {
	mapped := net.ParseIP("::ffff:10.0.0.1").To16()
	if got := ntop6(mapped); got != "::ffff:10.0.0.1" {
		t.Fatal(got)
	}
	if got := ntop6(net.IPv6zero); got != "::" {
		t.Fatal(got)
	}
}
