package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// luoke-core's socket, as luoke-core's task layer (V1 §2) is reached: one HTTP/1.1 request per connection, written by
// hand on a Unix socket. Whatever is wrong in a reply gives nothing, never a crash: a program with Full Disk Access
// reads it.

// HubSocket is luoke-core's socket: LUOKE_HUB_SOCKET (luoke-core sets it for its idle-time jobs), else where it always
// is.
func HubSocket(env map[string]string) string {
	if s, ok := env["LUOKE_HUB_SOCKET"]; ok {
		return s
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, "Library/Application Support/luoke-core/run/hub.sock")
}

// ShouldRemember says whether this run talks to luoke-core (the memory, the model): the installed app, or a
// development build pointed at a luoke-core of its own; and only with this Mac's own data directory (another one is a
// test).
func ShouldRemember(packaged, otherData bool, env map[string]string) bool {
	_, given := env["LUOKE_HUB_SOCKET"]
	return !otherData && (packaged || given)
}

// Environ is the process's environment as a map (the first of a repeated name, as Foundation's environment has it).
func Environ() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i > 0 {
			if _, seen := out[kv[:i]]; !seen {
				out[kv[:i]] = kv[i+1:]
			}
		}
	}
	return out
}

// sunPathMax is the room for a path in sockaddr_un (with its terminating zero).
const sunPathMax = 104

// hubConnect is a connection to luoke-core's socket, or nil; the caller closes it.
func hubConnect(socket string, timeout time.Duration) net.Conn {
	if len(socket) >= sunPathMax {
		return nil
	}
	c, err := net.DialTimeout("unix", socket, max(timeout, time.Second))
	if err != nil {
		return nil
	}
	return c
}

// hubExchange sends request and reads the reply until done says it is all there, the other side closes, 4 MB came, or
// the deadline: the reply so far, whether it was closed, and whether the deadline passed first.
func hubExchange(c net.Conn, request []byte, deadline time.Time, done func([]byte) bool) (reply []byte, closed, late bool, sent bool) {
	c.SetWriteDeadline(time.Now().Add(max(time.Until(deadline), time.Second)))
	if n, err := c.Write(request); err != nil || n != len(request) {
		return nil, false, false, false
	}
	buf := make([]byte, 65536)
	for len(reply) < 4<<20 {
		if !time.Now().Before(deadline) {
			return reply, false, true, true
		}
		c.SetReadDeadline(deadline)
		n, err := c.Read(buf)
		reply = append(reply, buf[:n]...)
		if n > 0 && done(reply) {
			break
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return reply, false, true, true
			}
			closed = true
			break
		}
	}
	return reply, closed, false, true
}

// askHub is one GET on luoke-core's socket (X-Luoke-Accessory as V1 asks), all of it within timeout; the JSON body of
// a 200, else nil.
func askHub(socket, path, accessory string, timeout time.Duration) any {
	deadline := time.Now().Add(timeout)
	c := hubConnect(socket, timeout)
	if c == nil {
		return nil
	}
	defer c.Close()
	req := "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nX-Luoke-Accessory: " + accessory + "\r\nConnection: close\r\n\r\n"
	reply, _, late, sent := hubExchange(c, []byte(req), deadline, hubComplete)
	if !sent || late {
		return nil
	}
	v, ok := hubBody(reply)
	if !ok {
		return nil
	}
	return v
}

var crlf2 = []byte("\r\n\r\n")

// hubComplete says whether a reply with a Content-Length has all of its body (then there is no need to wait for the
// close).
func hubComplete(reply []byte) bool {
	split := bytes.Index(reply, crlf2)
	if split < 0 {
		return false
	}
	n, ok := hubContentLength(reply[:split])
	return ok && len(reply)-(split+4) >= n
}

func hubContentLength(head []byte) (int, bool) {
	for _, line := range strings.Split(strings.ToLower(decodeUTF8(head)), "\r\n") {
		if strings.HasPrefix(line, "content-length:") {
			n, err := strconv.Atoi(strings.Trim(line[len("content-length:"):], " \t"))
			return n, err == nil && n >= 0
		}
	}
	return 0, false
}

// hubBody is the JSON body of an HTTP/1.1 reply with status 200 (Content-Length, chunked, or to the end).
func hubBody(reply []byte) (any, bool) {
	split := bytes.Index(reply, crlf2)
	if split < 0 {
		return nil, false
	}
	head := strings.ToLower(decodeUTF8(reply[:split]))
	if !strings.HasPrefix(head, "http/1.1 200") && !strings.HasPrefix(head, "http/1.0 200") {
		return nil, false
	}
	rest := reply[split+4:]
	if strings.Contains(head, "transfer-encoding: chunked") {
		var out []byte
		for {
			line := bytes.Index(rest, []byte("\r\n"))
			if line < 0 {
				break
			}
			size, err := strconv.ParseInt(strings.Trim(firstField(decodeUTF8(rest[:line]), ";"), " \t"), 16, 64)
			if err != nil || size < 0 {
				return nil, false
			}
			if size == 0 {
				break
			}
			start := line + 2
			if int64(len(rest)-start) < size {
				return nil, false
			}
			end := start + int(size)
			out = append(out, rest[start:end]...)
			rest = rest[end:]
			if len(rest) >= 2 {
				rest = rest[2:]
			} else {
				rest = nil
			}
		}
		rest = out
	} else if n, ok := hubContentLength(reply[:split]); ok && n < len(rest) {
		rest = rest[:n]
	}
	return parseJSON(rest)
}

// firstField is the first piece of s between seps that is not empty (Swift's split(separator:).first), or "".
func firstField(s, sep string) string {
	for _, p := range strings.Split(s, sep) {
		if p != "" {
			return p
		}
	}
	return ""
}

// parseJSON is JSONSerialization's reading of any JSON value (numbers as float64).
func parseJSON(b []byte) (any, bool) {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return nil, false
	}
	return v, true
}

// decodeUTF8 is String(decoding:as: UTF8.self): each byte that is not part of valid UTF-8 becomes U+FFFD.
func decodeUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		sb.WriteRune(r)
		b = b[n:]
	}
	return sb.String()
}

func jsonGet(v any, key string) any {
	if o, ok := v.(map[string]any); ok {
		return o[key]
	}
	return nil
}

func jsonString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// jsonInt is a whole number (under 1e15 either way), as the Swift version's JSON.int.
func jsonInt(v any) (int, bool) {
	f, ok := v.(float64)
	if !ok || f != float64(int64(f)) || f >= 1e15 || f <= -1e15 {
		return 0, false
	}
	return int(f), true
}
