package service

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// Writes records into the user's memory through luoke-core's copy of luoke_mem (luoke-mem 0.26.0's record command):
// this program has no Python of its own. Run with luoke-core's Python -- only its signed one -- with a bare environment,
// from "/". Memory not there, luoke-core slow or not answering, a record refused: the round and the clean go on as
// they would; that one is just not remembered. Nothing here waits long: luoke-core gets 2 seconds to answer, the write
// 5. Unlike the Swift version the Python is not made responsible for itself (no disclaim): the scanner has no Full
// Disk Access of its own, it uses 螺壳's, which started it, and that Python is 螺壳's anyway (11-05).

// Line is the line luoke_mem record takes: topic, speaker, kind, text, happened_at as local "YYYY-MM-DD HH:MM:SS",
// data, and ref when there is one; compact, keys sorted.
func (r MemoryRecord) Line() []byte {
	o := map[string]any{"topic": r.Topic, "speaker": r.Speaker, "kind": r.Kind, "text": r.Text,
		"happened_at": r.HappenedAt.Local().Format("2006-01-02 15:04:05"), "data": r.Data}
	if r.Data == nil {
		o["data"] = map[string]any{}
	}
	if r.Ref != "" {
		o["ref"] = r.Ref
	}
	var b strings.Builder
	writeCompactJSON(&b, o)
	b.WriteByte('\n')
	return []byte(b.String())
}

// writeCompactJSON writes v as the Swift version's JSON.serialized: compact, keys sorted, whole numbers without a
// fraction, non-ASCII kept as UTF-8.
func writeCompactJSON(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		quoteCompact(b, x)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case float64:
		switch {
		case x == math.Round(x) && math.Abs(x) < 1e15:
			b.WriteString(strconv.FormatInt(int64(x), 10))
		case math.IsInf(x, 0) || math.IsNaN(x):
			b.WriteString("null")
		default:
			b.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
		}
	case []string:
		b.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			quoteCompact(b, s)
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCompactJSON(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			quoteCompact(b, k)
			b.WriteByte(':')
			writeCompactJSON(b, x[k])
		}
		b.WriteByte('}')
	default:
		// Anything else (a slice of maps…): through encoding/json, read back, and written the same way.
		data, err := json.Marshal(x)
		var back any
		if err != nil || json.Unmarshal(data, &back) != nil {
			b.WriteString("null")
			return
		}
		writeCompactJSON(b, back)
	}
}

func quoteCompact(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x2028 || r == 0x2029:
			b.WriteString(`\u`)
			h := strconv.FormatInt(int64(r), 16)
			b.WriteString(strings.Repeat("0", 4-len(h)) + h)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// MemoryRecorder is what Config.Remember is for this run (nil: nothing is written, as ShouldRemember). env is read now
// and kept: a test luoke-core's socket and memory (LUOKE_HUB_SOCKET, LUOKE_HOME) stay with the records whatever this
// process's environment becomes.
func MemoryRecorder(packaged, otherData bool, version string, env map[string]string) func([]MemoryRecord) {
	if !ShouldRemember(packaged, otherData, env) {
		return nil
	}
	kept := map[string]string{}
	for k, v := range env {
		kept[k] = v
	}
	return func(records []MemoryRecord) { rememberRecords(records, version, kept) }
}

// rememberRecords writes records now; how many went in. Errors are swallowed on purpose (see above).
func rememberRecords(records []MemoryRecord, version string, env map[string]string) int {
	if len(records) == 0 {
		return 0
	}
	tasks := askHub(HubSocket(env), "/tasks", "luoke-scan/"+version, 2*time.Second)
	if tasks == nil {
		return 0
	}
	python, ok := memInterpreter(tasks, memTrusted)
	if !ok {
		return 0
	}
	return memWrite(records, python, "", 5*time.Second, env)
}

// memEnvironment is the environment luoke_mem gets: where home and luoke's data are (as luoke-core passes them to the
// commands it runs: a test luoke-core's LUOKE_HOME keeps the record out of the real memory), nothing else of this
// process's.
func memEnvironment(env map[string]string) map[string]string {
	home, ok := env["HOME"]
	if !ok {
		home, _ = os.UserHomeDir()
	}
	out := map[string]string{"HOME": home, "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "LANG": "en_US.UTF-8"}
	for _, k := range []string{"LUOKE_HOME", "LUOKE_MEM_TEST"} {
		if v, ok := env[k]; ok {
			out[k] = v
		}
	}
	return out
}

// memWrite runs `<python> -I -B -m luoke_mem record --tool luoke-scan` with the records on its standard input, from
// "/", within timeout; counts the {"id": N} lines it answers. path: a memory file of its own (tests).
func memWrite(records []MemoryRecord, python, path string, timeout time.Duration, env map[string]string) int {
	args := []string{"-I", "-B", "-m", "luoke_mem", "record", "--tool", "luoke-scan"}
	if path != "" {
		args = append(args, "--path", path)
	}
	var input []byte
	for _, r := range records {
		input = append(input, r.Line()...)
	}
	res := core.Run(python, args, core.RunOpts{Dir: "/", Env: memEnvironment(env), Timeout: timeout, Stdin: input})
	n := 0
	for _, line := range strings.Split(res.Stdout, "\n") {
		if line == "" {
			continue
		}
		var o any
		if json.Unmarshal([]byte(line), &o) != nil {
			continue
		}
		if m, ok := o.(map[string]any); ok {
			if _, has := m["id"]; has {
				n++
			}
		}
	}
	return n
}

// memTrusted says whether a Python may be run: signed by luoke's Team (tests put in their own).
var memTrusted = SignedByLuoke

// memInterpreter is the Python to run luoke_mem with: luoke_mem.python in GET /tasks, else the one next to its path
// (site-packages, three folders down from the Python's own folder). Only luoke-core's own app's, signed by luoke's
// Team (trusted): an answer from whatever LUOKE_HUB_SOCKET points at decides nothing on its own.
func memInterpreter(tasks any, trusted func(string) bool) (string, bool) {
	mem := jsonGet(tasks, "luoke_mem")
	if mem == nil {
		return "", false
	}
	candidate, ok := jsonString(jsonGet(mem, "python"))
	if !ok {
		p, ok := jsonString(jsonGet(mem, "path"))
		if !ok {
			return "", false
		}
		candidate = filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(p))), "bin/python3")
	}
	real, ok := realPath(candidate)
	if !ok || !luokeCorePython(real) || !trusted(real) {
		return "", false
	}
	return real, true
}

var luokeCorePythonPath = regexp.MustCompile(`\.app/Contents/Resources/python/bin/python3(\.[0-9]+)?$`)

// luokeCorePython: <…>.app/Contents/Resources/python/bin/python3[.N] of an app whose bundle id is luoke-core's, and
// executable.
func luokeCorePython(path string) bool {
	loc := luokeCorePythonPath.FindStringIndex(path)
	if loc == nil {
		return false
	}
	app := path[:loc[0]] + ".app"
	info := core.ReadPlistDict(filepath.Join(app, "Contents/Info.plist"))
	return core.PlistString(info, "CFBundleIdentifier") == "ai.luoke.core" && core.IsExecutable(path)
}

var teamID = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// SignedByLuoke says whether the program carries a valid signature from luoke's Team (Developer ID), as
// /usr/bin/codesign checks it. The Team is the release's (core.ReleaseTeam): a development build has none, and trusts
// nothing.
func SignedByLuoke(path string) bool {
	team := core.ReleaseTeam
	if !teamID.MatchString(team) {
		return false
	}
	req := `=anchor apple generic and certificate leaf[subject.OU] = "` + team + `" and certificate 1[field.1.2.840.113635.100.6.2.6]`
	r := core.Run("/usr/bin/codesign", []string{"--verify", "-R", req, path}, core.RunOpts{Timeout: 20 * time.Second})
	return r.Status == 0 && !r.TimedOut
}
