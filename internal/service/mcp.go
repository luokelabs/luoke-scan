package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
)

// The subset of MCP 2026-07-28 that luoke-agent's tool protocol (version 1) uses: JSON-RPC, one answer per request.
const (
	ProtocolVersion = "2026-07-28"
	AgentProtocol   = 1
	metaVersion     = "io.modelcontextprotocol/protocolVersion"
	metaServer      = "io.modelcontextprotocol/serverInfo"
	UserAction      = "ai.luoke/user-action" // every call that changes something carries where the user clicked
	whereKey        = "ai.luoke/where"
	parseError      = -32700
	invalidRequest  = -32600
	methodNotFound  = -32601
	invalidParams   = -32602
	internalError   = -32603
	resourceMissing = -32002
	MaxBody         = 1 << 20
)

// O is a JSON object; A an array.
type (
	O = map[string]any
	A = []any
)

// ToolOutput is what a tool returns: a sentence for the user, and structured content (a card, done…).
type ToolOutput struct {
	Text  string
	Card  []any
	Done  *bool
	Extra O
}

// ToolFailure is a tool that could not do it: a sentence and a code (not_ready, needs_setup, stale, invalid, failed).
type ToolFailure struct {
	Code, Message string
	Card          []any
}

func (f *ToolFailure) Error() string { return f.Code + ": " + f.Message }

// Fail makes a ToolFailure.
func Fail(code, message string) error { return &ToolFailure{Code: code, Message: message} }

// ToolFunc runs a tool with its arguments and the request's _meta.
type ToolFunc func(args O, meta O) (ToolOutput, error)

type tool struct {
	name     string
	spec     O
	readOnly bool
	required []string
	run      ToolFunc
}

type resource struct {
	spec     O
	read     func() any
	readMeta func(meta O) any // read with the request's _meta (what the agent core can draw), when it matters
	// readArgs: read with arguments, <uri>?<key>=<value>&… (tool protocol §4 pageArgs); none, an empty map
	readArgs func(args map[string]string) any
}

// Server answers MCP requests from its tools and resources.
type Server struct {
	name, version string
	mu            sync.Mutex
	tools         []tool
	resources     map[string]resource
	// out is where Serve writes: a slow tool's notifications go out on it before its answer.
	outMu sync.Mutex
	out   io.Writer
}

// progressMessageMax is the most a progress message says, in characters (the window draws it on one line).
const progressMessageMax = 60

// Progress reports how far a slow call has got (tool protocol §5): MCP's notifications/progress on the request's
// progressToken, with the item being done (from 1), how many there are, and what it is doing now. A no-op when the
// request carries no token, or when nothing is served (a test calling the tool directly).
func (s *Server) Progress(meta O) func(n, total int, message string) {
	token := meta["progressToken"]
	switch t := token.(type) {
	case string:
		if t == "" {
			token = nil
		}
	case int64, float64: // what normalizeNumbers leaves
	default:
		token = nil
	}
	if s == nil || token == nil {
		return func(int, int, string) {}
	}
	return func(n, total int, message string) {
		if r := []rune(message); len(r) > progressMessageMax {
			message = string(r[:progressMessageMax-1]) + "…"
		}
		s.write(O{"jsonrpc": "2.0", "method": "notifications/progress",
			"params": O{"progressToken": token, "progress": n, "total": total, "message": message}})
	}
}

// write sends one message on what Serve writes to; nothing when not serving.
func (s *Server) write(v any) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	if s.out != nil {
		writeLine(s.out, v)
	}
}

func NewServer(name, version string) *Server {
	return &Server{name: name, version: version, resources: map[string]resource{}}
}

// ToolSpec describes a tool's inputs and nature.
type ToolSpec struct {
	Title, Description string
	Properties         O
	Required           []string
	ReadOnly           bool
	Destructive        bool
	MacOnly            bool
}

// Tool registers a tool.
func (s *Server) Tool(name string, t ToolSpec, run ToolFunc) {
	props := t.Properties
	if props == nil {
		props = O{}
	}
	req := t.Required
	if req == nil {
		req = []string{}
	}
	spec := O{"name": name, "title": t.Title, "description": t.Description,
		"inputSchema": O{"type": "object", "properties": props, "required": req},
		"annotations": O{"readOnlyHint": t.ReadOnly, "destructiveHint": t.Destructive}}
	if t.MacOnly {
		spec["_meta"] = O{whereKey: "mac"}
	}
	s.mu.Lock()
	s.tools = append(s.tools, tool{name, spec, t.ReadOnly, t.Required, run})
	s.mu.Unlock()
}

// Resource registers a resource.
func (s *Server) Resource(uri, name string, read func() any) {
	s.mu.Lock()
	s.resources[uri] = resource{spec: O{"uri": uri, "name": name, "mimeType": "application/json"}, read: read}
	s.mu.Unlock()
}

// ResourceMeta registers a resource read with the request's _meta: a page drawn in the forms the agent core says it
// knows (Features).
func (s *Server) ResourceMeta(uri, name string, read func(meta O) any) {
	s.mu.Lock()
	s.resources[uri] = resource{spec: O{"uri": uri, "name": name, "mimeType": "application/json"}, readMeta: read}
	s.mu.Unlock()
}

// ResourceArgs registers a resource read with arguments: <uri>?<key>=<value>&… (keys in order, values percent-encoded,
// as tool protocol §4 pageArgs has them); read with none, or with a query that does not parse, it gets an empty map.
// A key given twice: its first value.
func (s *Server) ResourceArgs(uri, name string, read func(args map[string]string) any) {
	s.mu.Lock()
	s.resources[uri] = resource{spec: O{"uri": uri, "name": name, "mimeType": "application/json"}, readArgs: read}
	s.mu.Unlock()
}

// queryArgs: a query's keys and their first values; empty when it does not parse.
func queryArgs(query string) map[string]string {
	args := map[string]string{}
	values, err := url.ParseQuery(query)
	if err != nil {
		return args
	}
	for k, v := range values {
		if len(v) > 0 {
			args[k] = v[0]
		}
	}
	return args
}

// Handle answers one JSON-RPC message; nil for a notification.
func (s *Server) Handle(message any) any {
	msg, ok := message.(map[string]any)
	method, okm := msg["method"].(string)
	if !ok || msg["jsonrpc"] != "2.0" || !okm {
		var id any
		if ok {
			id = msg["id"]
		}
		return rpcError(id, invalidRequest, "不是 JSON-RPC 2.0 请求", nil)
	}
	rid, has := msg["id"]
	if !has {
		return nil
	}
	params := msg["params"]
	if params == nil {
		params = O{}
	}
	p, ok := params.(map[string]any)
	if !ok {
		return rpcError(rid, invalidParams, "params 要是对象", nil)
	}
	metaV := p["_meta"]
	if metaV == nil {
		metaV = O{}
	}
	meta, ok := metaV.(map[string]any)
	if !ok {
		return rpcError(rid, invalidParams, "_meta 要是对象", nil)
	}
	if v, has := meta[metaVersion]; has && v != ProtocolVersion {
		return rpcError(rid, invalidParams, "不支持这个协议版本", O{"supportedVersions": A{ProtocolVersion}})
	}
	s.mu.Lock()
	tools := append([]tool{}, s.tools...)
	resources := s.resources
	s.mu.Unlock()
	switch method {
	case "server/discover":
		caps := O{}
		if len(tools) > 0 {
			caps["tools"] = O{}
		}
		if len(resources) > 0 {
			caps["resources"] = O{}
		}
		return result(rid, O{"supportedVersions": A{ProtocolVersion}, "capabilities": caps,
			"_meta": O{metaServer: O{"name": s.name, "version": s.version}}})
	case "resources/list":
		keys := make([]string, 0, len(resources))
		for k := range resources {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		list := A{}
		for _, k := range keys {
			list = append(list, resources[k].spec)
		}
		return result(rid, O{"resources": list})
	case "resources/read":
		uri, _ := p["uri"].(string)
		r, ok := resources[uri]
		query := ""
		if base, q, cut := strings.Cut(uri, "?"); !ok && cut {
			if br, has := resources[base]; has && br.readArgs != nil { // read with arguments (§4 pageArgs)
				r, ok, query = br, true, q
			}
		}
		if !ok {
			return rpcError(rid, resourceMissing, "没有这个资源", O{"uri": p["uri"]})
		}
		var v any
		switch {
		case r.readArgs != nil:
			v = r.readArgs(queryArgs(query))
		case r.readMeta != nil:
			v = r.readMeta(meta)
		default:
			v = r.read()
		}
		text, isString := v.(string)
		if !isString {
			text = Serialize(v)
		}
		return result(rid, O{"contents": A{O{"uri": uri, "mimeType": r.spec["mimeType"], "text": text}}})
	case "tools/list":
		list := A{}
		for _, t := range tools {
			list = append(list, t.spec)
		}
		return result(rid, O{"tools": list})
	case "tools/call":
		return s.call(rid, p, meta, tools)
	}
	return rpcError(rid, methodNotFound, "没有这个方法："+method, nil)
}

func (s *Server) call(rid any, p, meta O, tools []tool) any {
	name, _ := p["name"].(string)
	var t *tool
	for i := range tools {
		if tools[i].name == name {
			t = &tools[i]
		}
	}
	if t == nil {
		if name == "" {
			name = "?"
		}
		return rpcError(rid, invalidParams, "没有这个工具："+name, nil)
	}
	argsV := p["arguments"]
	if argsV == nil {
		argsV = O{}
	}
	args, ok := argsV.(map[string]any)
	if !ok {
		return rpcError(rid, invalidParams, "arguments 要是对象", nil)
	}
	if !t.readOnly && !validUserAction(meta[UserAction]) {
		return result(rid, toolError("needs_user_action", "这个操作要你在卡片上点过才能执行。", nil))
	}
	var missing []string
	for _, r := range t.required {
		if _, ok := args[r]; !ok {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return result(rid, toolError("invalid", "缺少参数："+join(missing, "、"), nil))
	}
	out, err := t.run(args, meta)
	if err != nil {
		if f, ok := err.(*ToolFailure); ok {
			return result(rid, toolError(f.Code, f.Message, f.Card))
		}
		fmt.Fprintf(os.Stderr, "luoke-scan: 工具 %s 出错 %T\n", name, err)
		return rpcError(rid, internalError, "工具内部出错", nil)
	}
	structured := O{}
	for k, v := range out.Extra {
		structured[k] = v
	}
	if out.Card != nil {
		structured["card"] = out.Card
	}
	if out.Done != nil {
		structured["done"] = *out.Done
	}
	r := O{"content": A{O{"type": "text", "text": out.Text}}, "isError": false}
	if len(structured) > 0 {
		r["structuredContent"] = structured
	}
	return result(rid, r)
}

func validUserAction(v any) bool {
	o, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"surfaceId", "componentId", "at"} {
		if s, _ := o[k].(string); s == "" {
			return false
		}
	}
	return true
}

func toolError(code, message string, card []any) O {
	s := O{"code": code}
	if card != nil {
		s["card"] = card
	}
	return O{"content": A{O{"type": "text", "text": message}}, "structuredContent": s, "isError": true}
}

func result(rid any, r O) any {
	r["resultType"] = "complete"
	return O{"jsonrpc": "2.0", "id": rid, "result": r}
}

func rpcError(rid any, code int, message string, data any) any {
	e := O{"code": code, "message": message}
	if data != nil {
		e["data"] = data
	}
	return O{"jsonrpc": "2.0", "id": rid, "error": e}
}

// Serialize writes JSON compactly with keys sorted and non-ASCII kept (as the Swift version's JSON.serialized).
func Serialize(v any) string {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	e.Encode(v)
	return string(bytes.TrimRight(buf.Bytes(), "\n"))
}

// Bool is a pointer to b (ToolOutput.Done).
func Bool(b bool) *bool { return &b }

func join(s []string, sep string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += sep
		}
		out += x
	}
	return out
}

// MaxMessage is the most one message may take (the Swift version's request body limit, SocketServer.maxBody).
const MaxMessage = 1 << 20

// errTooBig: a message went past MaxMessage.
var errTooBig = errors.New("message too big")

// perMessage counts what a decoder reads for the message it is on: reset after each message to what the decoder
// already holds of the next one, so a long session is never cut off by what it read before.
type perMessage struct {
	r   io.Reader
	n   int64
	max int64
}

func (p *perMessage) Read(b []byte) (int, error) {
	if p.n >= p.max {
		return 0, errTooBig
	}
	if int64(len(b)) > p.max-p.n {
		b = b[:p.max-p.n]
	}
	n, err := p.r.Read(b)
	p.n += int64(n)
	return n, err
}

// Serve answers MCP on r and w: one request read to the end (what a test sends), or a session of one JSON-RPC message
// per line. The exit status: 0 when every message was answered (or was a notification), 3 when the input was empty or
// a message went past MaxMessage (then nothing more is read).
func (s *Server) Serve(r io.Reader, w io.Writer) int {
	s.outMu.Lock()
	s.out = w
	s.outMu.Unlock()
	defer func() {
		s.outMu.Lock()
		s.out = nil
		s.outMu.Unlock()
	}()
	in := &perMessage{r: r, max: MaxMessage}
	dec := json.NewDecoder(in)
	dec.UseNumber()
	n := 0
	for {
		var msg any
		err := dec.Decode(&msg)
		if err == io.EOF {
			if n == 0 {
				return 3
			}
			return 0
		}
		if errors.Is(err, errTooBig) {
			return 3
		}
		if err != nil {
			s.write(rpcError(nil, parseError, "不是 JSON", nil))
			return 0
		}
		n++
		in.n = int64(dec.Buffered().(*bytes.Reader).Len()) // what is already read belongs to the next message
		if reply := s.Handle(normalizeNumbers(msg)); reply != nil {
			s.write(reply)
		}
	}
}

func writeLine(w io.Writer, v any) {
	io.WriteString(w, Serialize(v)+"\n")
}

// normalizeNumbers turns json.Number into int64 when whole, else float64.
func normalizeNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		f, _ := x.Float64()
		return f
	case map[string]any:
		for k, e := range x {
			x[k] = normalizeNumbers(e)
		}
	case []any:
		for i, e := range x {
			x[i] = normalizeNumbers(e)
		}
	}
	return v
}
