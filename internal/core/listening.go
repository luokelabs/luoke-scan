package core

import (
	"encoding/binary"
	"net"
	"strconv"
)

// struct socket_fdinfo (sys/proc_info.h), as the SDK lays it out on 64-bit macOS: the offsets of what is read.
const (
	sockFDInfoSize   = 792
	sockOffKind      = 256 // psi.soi_kind
	sockOffTCPState  = 344 // psi.soi_proto.pri_tcp.tcpsi_state
	sockOffLocalPort = 268 // ...tcpsi_ini.insi_lport (an int holding the port in network order)
	sockOffVFlag     = 288 // ...tcpsi_ini.insi_vflag
	sockOffLocalAddr = 312 // ...tcpsi_ini.insi_laddr (ina_6)
	sockOffLocalV4   = 324 // ...insi_laddr.ina_46.i46a_addr4

	proxFDTypeSocket    = 2 // PROX_FDTYPE_SOCKET
	procPidFDSocketInfo = 3 // PROC_PIDFDSOCKETINFO
	sockInfoTCP         = 2 // SOCKINFO_TCP
	tcpStateListen      = 1 // TSI_S_LISTEN
	iniIPv6             = 2 // INI_IPV6
)

// procListeningSockets are the listening TCP sockets of a process (this user's: others' cannot be looked into).
func procListeningSockets(pid int32) []ListeningSocket {
	fds := make([]byte, 8*4096)
	n, e := procInfo(procCallPidInfo, int(pid), procPidListFDs, 0, fds)
	if e != 0 || n <= 0 {
		return nil
	}
	info := make([]byte, sockFDInfoSize)
	var out []ListeningSocket
	for j := 0; j+8 <= n; j += 8 {
		if binary.LittleEndian.Uint32(fds[j+4:j+8]) != proxFDTypeSocket {
			continue
		}
		fd := int32(binary.LittleEndian.Uint32(fds[j : j+4]))
		k, e := procInfo(procCallPidFDInfo, int(pid), procPidFDSocketInfo, uint64(fd), info)
		if e != 0 || k != sockFDInfoSize {
			continue
		}
		if l, ok := listeningSocket(info); ok {
			out = append(out, l)
		}
	}
	return out
}

// listeningSocket reads one socket_fdinfo: a TCP socket in LISTEN, its port and address as inet_ntop writes them.
func listeningSocket(info []byte) (ListeningSocket, bool) {
	le := binary.LittleEndian
	if le.Uint32(info[sockOffKind:]) != sockInfoTCP || le.Uint32(info[sockOffTCPState:]) != tcpStateListen {
		return ListeningSocket{}, false
	}
	port := int(info[sockOffLocalPort])<<8 | int(info[sockOffLocalPort+1])
	if info[sockOffVFlag]&iniIPv6 != 0 {
		return ListeningSocket{Port: port, Address: ntop6(info[sockOffLocalAddr : sockOffLocalAddr+16])}, true
	}
	a := info[sockOffLocalV4 : sockOffLocalV4+4]
	return ListeningSocket{Port: port, Address: net.IPv4(a[0], a[1], a[2], a[3]).String()}, true
}

// ntop6 is an IPv6 address as inet_ntop(AF_INET6) writes it: an IPv4-mapped one as ::ffff:a.b.c.d (Go would write
// only the IPv4 part).
func ntop6(b []byte) string {
	ip := net.IP(append([]byte(nil), b...))
	if v4 := ip.To4(); v4 != nil && b[10] == 0xff && b[11] == 0xff {
		return "::ffff:" + strconv.Itoa(int(v4[0])) + "." + strconv.Itoa(int(v4[1])) + "." + strconv.Itoa(int(v4[2])) + "." + strconv.Itoa(int(v4[3]))
	}
	return ip.String()
}
