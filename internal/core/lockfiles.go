package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
)

// Lockfiles: what a project's package managers wrote down they installed, read for package names and versions only.
// Small parsers of our own (standard library only), each reading just the lines or keys that name a package from
// a registry; workspace members, local folders, git checkouts and patches are left out (the list names registry
// packages). A file a parser cannot read gives nothing, never a guess.

// DepPkg is one package a lockfile names.
type DepPkg struct {
	Eco, Name, Version string
	// Source: the registry it came from when that is not the public one (its host, or the index's name); "" public.
	// A package of the same name from a company's own registry may be theirs, not the one on the list.
	Source string
	// Where: the package's own folder when known (a global install's dependencies); "" the source's path.
	Where string
}

// publicRegistryHosts are the public registries' hosts: a package from these has no Source.
var publicRegistryHosts = map[string]bool{"registry.npmjs.org": true, "registry.npmjs.com": true, "registry.yarnpkg.com": true,
	"pypi.org": true, "pypi.python.org": true, "files.pythonhosted.org": true}

// registryHost: a registry URL's host, "" for a public one.
func registryHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if publicRegistryHosts[h] {
		return ""
	}
	return h
}

// npmResolved: where npm or yarn says a package was fetched from. ok false when not from a registry: git, a local file
// or folder, a tarball at some other URL (a registry's tarballs are at …/<name>/-/<file>.tgz). An empty one (bundled
// with its parent, or a lockfile written without them) is taken as the public registry.
func npmResolved(resolved string) (string, bool) {
	resolved = strings.Trim(strings.TrimSpace(resolved), `"`)
	if resolved == "" {
		return "", true
	}
	u, err := url.Parse(resolved)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", false
	}
	if !strings.Contains(u.Path, "/-/") || !strings.HasSuffix(u.Path, ".tgz") {
		return "", false
	}
	return registryHost(resolved), true
}

// Lockfiles the rule reads, by file name, with their ecosystem.
var lockfileEcosystems = map[string]string{
	"package-lock.json":   "npm",
	"npm-shrinkwrap.json": "npm",
	"pnpm-lock.yaml":      "npm",
	"yarn.lock":           "npm",
	"bun.lock":            "npm",
	"uv.lock":             "PyPI",
	"poetry.lock":         "PyPI",
	"Pipfile.lock":        "PyPI",
	"Cargo.lock":          "crates.io",
}

// IsLockfile says whether a file name is one of the lockfiles read.
func IsLockfile(name string) bool { _, ok := lockfileEcosystems[name]; return ok }

// maxLockPackages: different packages one lockfile may name. A real one names tens of thousands at most; one past this
// is not read (and is said to be too large), so a made-up lockfile cannot make a round hold millions of them.
var maxLockPackages = 200_000

// Why a lockfile was not read: not one of the kinds read (or not readable as one), or naming too many packages.
var (
	errNotLockfile  = errors.New("not a lockfile it reads")
	errLockTooLarge = errors.New("lockfile names too many packages")
)

// ParseLockfile reads the packages in a lockfile named name (its base name). ok false: not one it reads, it could not be
// read as one, or it names more packages than are read from one.
func ParseLockfile(name string, data []byte) ([]DepPkg, bool) {
	out, err := parseLockfile(name, data)
	return out, err == nil
}

// parseLockfile: the packages, or errNotLockfile or errLockTooLarge. Read as it goes (line by line, or one JSON member
// at a time), never the whole file split or decoded at once, and each package kept once.
func parseLockfile(name string, data []byte) ([]DepPkg, error) {
	sink := &depSink{seen: map[DepPkg]bool{}, max: maxLockPackages}
	var ok bool
	switch name {
	case "package-lock.json", "npm-shrinkwrap.json":
		ok = parseNpmLock(data, sink)
	case "pnpm-lock.yaml":
		ok = parsePnpmLock(data, sink)
	case "yarn.lock":
		ok = parseYarnLock(data, sink)
	case "bun.lock":
		ok = parseBunLock(data, sink)
	case "uv.lock", "poetry.lock", "Cargo.lock":
		ok = parseTomlPackages(name, data, sink)
	case "Pipfile.lock":
		ok = parsePipfileLock(data, sink)
	}
	if sink.over {
		return nil, errLockTooLarge
	}
	if !ok {
		return nil, errNotLockfile
	}
	out := sink.out
	if out == nil {
		out = []DepPkg{}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Source < b.Source
	})
	return out, nil
}

// depSink keeps each package a lockfile names once, up to max; past it, over is set and the parsers stop.
type depSink struct {
	out  []DepPkg
	seen map[DepPkg]bool
	max  int
	over bool
}

func (s *depSink) add(d DepPkg) {
	if s.over || s.seen[d] {
		return
	}
	if len(s.out) >= s.max {
		s.over = true
		return
	}
	s.seen[d] = true
	s.out = append(s.out, d)
}

// eachLine calls fn with each line of data (without its \r\n), one at a time, until fn says stop.
func eachLine(data []byte, fn func(line string) bool) {
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		var line []byte
		if i < 0 {
			line, data = data, nil
		} else {
			line, data = data[:i], data[i+1:]
		}
		if !fn(string(bytes.TrimRight(line, "\r"))) {
			return
		}
	}
}

// maxVersionLen: longest version read. Registries' versions are short; anything longer is not one.
const maxVersionLen = 64

// looksVersion: a version a registry gave: starts with a digit, at most maxVersionLen, only letters, digits and
// . + _ - (semver's and PEP 440's characters). Not a path, URL, tag or workspace marker, and nothing a lockfile could
// use to put a sentence into a card's title.
func looksVersion(v string) bool {
	if v == "" || len(v) > maxVersionLen || v[0] < '0' || v[0] > '9' {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !plainChar(v[i]) {
			return false
		}
	}
	return true
}

func plainChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '+' || c == '_' || c == '-'
}

// maxNameLen: longest package name read (npm allows 214).
const maxNameLen = 214

// looksName: a registry package's name as the lockfiles write it: letters, digits and . _ - ~, an npm scope's @ and /.
func looksName(n string) bool {
	if n == "" || len(n) > maxNameLen {
		return false
	}
	for i := 0; i < len(n); i++ {
		if c := n[i]; !plainChar(c) && c != '@' && c != '/' && c != '~' {
			return false
		}
	}
	return true
}

// plainSource: the registry a package came from as it is shown (a host or an index's name): ok as written when it is
// short and plain, else just "私有源".
func plainSource(src string) string {
	if src == "" {
		return ""
	}
	if len(src) > maxVersionLen {
		return "私有源"
	}
	for i := 0; i < len(src); i++ {
		if c := src[i]; !plainChar(c) || c == '+' {
			return "私有源"
		}
	}
	return src
}

// CleanDep: a package as it may be shown, or ok false when its name or version is not plain (left out, never shown).
func CleanDep(d DepPkg) (DepPkg, bool) {
	if !looksName(d.Name) || !looksVersion(d.Version) {
		return DepPkg{}, false
	}
	d.Source = plainSource(d.Source)
	return d, true
}

// splitSpec splits "name@version" at its last @ (a scope's leading @ is part of the name).
func splitSpec(s string) (string, string, bool) {
	i := strings.LastIndexByte(s, '@')
	if i <= 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// ---------------------------------------------------------------- npm: package-lock.json, npm-shrinkwrap.json

// jsonObject reads the object dec is at one member at a time: fn gets each key with dec at its value, and reads or
// skips it. false when it is not an object (or not JSON).
func jsonObject(dec *json.Decoder, fn func(key string) bool) bool {
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	for dec.More() {
		t, err := dec.Token()
		key, ok := t.(string)
		if err != nil || !ok || !fn(key) {
			return false
		}
	}
	t, err := dec.Token()
	return err == nil && t == json.Delim('}')
}

// jsonArray: the same for an array; fn reads or skips each element.
func jsonArray(dec *json.Decoder, fn func() bool) bool {
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return false
	}
	for dec.More() {
		if !fn() {
			return false
		}
	}
	t, err := dec.Token()
	return err == nil && t == json.Delim(']')
}

// jsonSkip reads past the value dec is at, a token at a time (never holding it whole).
func jsonSkip(dec *json.Decoder) bool {
	depth := 0
	for {
		t, err := dec.Token()
		if err != nil {
			return false
		}
		switch t {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth <= 0 {
			return true
		}
	}
}

// jsonString: the string dec is at, "" (and skipped) when it is something else.
func jsonString(dec *json.Decoder) (string, bool) {
	t, err := dec.Token()
	if err != nil {
		return "", false
	}
	switch v := t.(type) {
	case string:
		return v, true
	case json.Delim:
		if v == '{' || v == '[' {
			depth := 1
			for depth > 0 {
				t, err := dec.Token()
				if err != nil {
					return "", false
				}
				switch t {
				case json.Delim('{'), json.Delim('['):
					depth++
				case json.Delim('}'), json.Delim(']'):
					depth--
				}
			}
		}
	}
	return "", true
}

func newJSONDecoder(data []byte) *json.Decoder { return json.NewDecoder(bytes.NewReader(data)) }

// parseNpmLock: lockfile versions 2 and 3 list every installed folder under "packages" ("node_modules/a",
// "node_modules/a/node_modules/@s/b"; an alias has the real name in "name"); version 1 nests "dependencies", where an
// alias's version reads "npm:real@1.2.3". Version 2 has both: "packages" is read when it names anything.
func parseNpmLock(data []byte, sink *depSink) bool {
	dec := newJSONDecoder(data)
	version := 0
	sawDeps := false
	fromPackages := &depSink{seen: map[DepPkg]bool{}, max: sink.max}
	fromDeps := &depSink{seen: map[DepPkg]bool{}, max: sink.max}
	ok := jsonObject(dec, func(key string) bool {
		switch key {
		case "lockfileVersion":
			var v any
			if dec.Decode(&v) != nil {
				return false
			}
			if f, ok := v.(float64); ok {
				version = int(f)
			}
			return true
		case "packages":
			return jsonObject(dec, func(key string) bool {
				var p struct {
					Name     string `json:"name"`
					Version  string `json:"version"`
					Resolved string `json:"resolved"`
					Link     bool   `json:"link"`
				}
				if dec.Decode(&p) != nil {
					return false
				}
				i := strings.LastIndex(key, "node_modules/")
				if i < 0 || p.Link {
					return true // the project itself, or a workspace member
				}
				name := key[i+len("node_modules/"):]
				if p.Name != "" {
					name = p.Name
				}
				src, registry := npmResolved(p.Resolved)
				if registry && looksVersion(p.Version) && name != "" {
					fromPackages.add(DepPkg{Eco: "npm", Name: name, Version: p.Version, Source: src})
				}
				return !fromPackages.over
			})
		case "dependencies":
			sawDeps = true
			return npmV1Deps(dec, 0, fromDeps)
		}
		return jsonSkip(dec)
	})
	use := fromDeps
	if len(fromPackages.out) > 0 || fromPackages.over {
		use = fromPackages
	}
	if use.over {
		sink.over = true
		return false
	}
	if !ok {
		return false
	}
	for _, d := range use.out {
		sink.add(d)
	}
	return version > 0 || sawDeps
}

// npmV1Deps: version 1's nested "dependencies", streamed (up to 64 deep).
func npmV1Deps(dec *json.Decoder, depth int, sink *depSink) bool {
	return jsonObject(dec, func(name string) bool {
		var version, resolved string
		ok := jsonObject(dec, func(key string) bool {
			var ok bool
			switch key {
			case "version":
				version, ok = jsonString(dec)
			case "resolved":
				resolved, ok = jsonString(dec)
			case "dependencies":
				if depth < 64 {
					return npmV1Deps(dec, depth+1, sink)
				}
				ok = jsonSkip(dec)
			default:
				ok = jsonSkip(dec)
			}
			return ok
		})
		if !ok || sink.over {
			return false
		}
		v := version
		if real, ok := strings.CutPrefix(v, "npm:"); ok {
			if n, ver, ok := splitSpec(real); ok {
				name, v = n, ver
			}
		}
		if src, registry := npmResolved(resolved); registry && looksVersion(v) {
			sink.add(DepPkg{Eco: "npm", Name: name, Version: v, Source: src})
		}
		return !sink.over
	})
}

// ---------------------------------------------------------------- pnpm-lock.yaml

// parsePnpmLock reads the keys under "packages:" (and "snapshots:", lockfile 9): "/name/1.2.3_peer" (5.x),
// "/name@1.2.3(peer)" (6.x), "name@1.2.3" (9.x), scoped names quoted or not.
func parsePnpmLock(data []byte, sink *depSink) bool {
	section := ""
	sawVersion := false
	eachLine(data, func(line string) bool {
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			return true
		}
		if line[0] != ' ' {
			if strings.HasPrefix(line, "lockfileVersion:") {
				sawVersion = true
			}
			section = strings.TrimSuffix(strings.TrimSpace(line), ":")
			return true
		}
		if section != "packages" && section != "snapshots" {
			return true
		}
		if len(line) < 3 || line[:2] != "  " || line[2] == ' ' {
			return true
		}
		key := strings.TrimSpace(line)
		key = strings.TrimSuffix(key, " {}")
		if !strings.HasSuffix(key, ":") {
			return true
		}
		key = strings.Trim(strings.TrimSuffix(key, ":"), `'"`)
		if name, v, ok := pnpmKey(key); ok {
			sink.add(DepPkg{Eco: "npm", Name: name, Version: v})
		}
		return !sink.over
	})
	return sawVersion
}

func pnpmKey(key string) (string, string, bool) {
	k := key
	if i := strings.IndexByte(k, '('); i >= 0 {
		k = k[:i]
	}
	// 5.x: "/name/1.2.3" or "/@scope/name/1.2.3", peers after "_".
	if strings.HasPrefix(k, "/") {
		segs := strings.Split(k[1:], "/")
		n := 2
		if strings.HasPrefix(segs[0], "@") {
			n = 3
		}
		if len(segs) == n {
			name, v := strings.Join(segs[:n-1], "/"), segs[n-1]
			if j := strings.IndexByte(v, '_'); j >= 0 {
				v = v[:j]
			}
			if looksVersion(v) {
				return name, v, true
			}
			return "", "", false
		}
		k = k[1:]
	}
	// 6.x and 9.x: "name@1.2.3".
	name, v, ok := splitSpec(k)
	if !ok || name == "" || !looksVersion(v) {
		return "", "", false
	}
	return name, v, true
}

// ---------------------------------------------------------------- yarn.lock (classic and berry)

// parseYarnLock: a block per resolved package. Classic: the header's first spec gives the name ("alias@npm:real@^1"
// the real one), `version "1.2.3"` the version; a spec that is not a range or an npm: alias (git, github:, file:, a
// URL, a path) or a `resolved` that is not a registry's tarball is left out. Berry: `resolution: "name@npm:1.2.3"`; a resolution that is not from
// npm (workspace, patch, git, file) is left out.
func parseYarnLock(data []byte, sink *depSink) bool {
	header, version, resolution, resolved := "", "", "", ""
	sawBlock := false
	flush := func() {
		defer func() { header, version, resolution, resolved = "", "", "", "" }()
		if header == "" || header == "__metadata" {
			return
		}
		if resolution != "" {
			r := strings.Trim(resolution, `"`)
			start := 0
			if strings.HasPrefix(r, "@") {
				start = 1
			}
			i := strings.Index(r[start:], "@npm:")
			if i < 0 {
				return
			}
			name, v := r[:start+i], r[start+i+len("@npm:"):]
			if looksVersion(v) {
				sink.add(DepPkg{Eco: "npm", Name: name, Version: v})
			}
			return
		}
		first := strings.TrimSpace(strings.SplitN(header, ",", 2)[0])
		first = strings.Trim(first, `"`)
		var name string
		if i := strings.Index(first, "@npm:"); i > 0 {
			// "alias@npm:real@^1": the real name; "name@npm:^1": the name.
			name = first[:i]
			if n, _, ok := splitSpec(first[i+len("@npm:"):]); ok {
				name = n
			}
		} else {
			n, rng, ok := splitSpec(first)
			if !ok || !yarnRegistryRange(rng) {
				return
			}
			name = n
		}
		src, registry := npmResolved(resolved)
		v := strings.Trim(version, `"`)
		if registry && looksVersion(v) {
			sink.add(DepPkg{Eco: "npm", Name: name, Version: v, Source: src})
		}
	}
	eachLine(data, func(line string) bool {
		if line == "" || strings.HasPrefix(line, "#") {
			return true
		}
		if line[0] != ' ' {
			flush()
			if strings.HasSuffix(line, ":") {
				header = strings.TrimSuffix(line, ":")
				sawBlock = true
			}
			return !sink.over
		}
		if len(line) > 2 && line[2] == ' ' {
			return true // deeper: dependencies of the block
		}
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "version:"):
			version = strings.TrimSpace(strings.TrimPrefix(t, "version:"))
		case strings.HasPrefix(t, "version "):
			version = strings.TrimSpace(strings.TrimPrefix(t, "version "))
		case strings.HasPrefix(t, "resolution:"):
			resolution = strings.TrimSpace(strings.TrimPrefix(t, "resolution:"))
		case strings.HasPrefix(t, "resolved "):
			resolved = strings.TrimSpace(strings.TrimPrefix(t, "resolved "))
		}
		return true
	})
	flush()
	return sawBlock
}

// yarnRegistryRange: a classic spec's range that is resolved from a registry: a semver range or a dist-tag, not
// git, github:, file:, link:, a URL, a path or a user/repo shorthand.
func yarnRegistryRange(r string) bool {
	r = strings.Trim(r, `"`)
	if r == "" || strings.HasPrefix(r, ".") {
		return false
	}
	return !strings.ContainsAny(r, ":/#")
}

// ---------------------------------------------------------------- bun.lock (text)

// parseBunLock: bun's text lockfile is JSON with trailing commas; "packages" maps a key to ["name@version", …].
func parseBunLock(data []byte, sink *depSink) bool {
	dec := newJSONDecoder(stripJSONC(data))
	sawVersion := false
	ok := jsonObject(dec, func(key string) bool {
		switch key {
		case "lockfileVersion":
			sawVersion = true
			return jsonSkip(dec)
		case "packages":
			return jsonObject(dec, func(string) bool {
				var spec, reg string
				i := 0
				ok := jsonArray(dec, func() bool {
					i++
					switch i {
					case 1:
						var ok bool
						spec, ok = jsonString(dec)
						return ok
					case 2:
						// The registry it came from, "" for the default one.
						var ok bool
						reg, ok = jsonString(dec)
						return ok
					}
					return jsonSkip(dec)
				})
				if !ok {
					return false
				}
				if name, v, ok := splitSpec(spec); ok && looksVersion(v) {
					sink.add(DepPkg{Eco: "npm", Name: name, Version: v, Source: registryHost(reg)})
				}
				return !sink.over
			})
		}
		return jsonSkip(dec)
	})
	return ok && sawVersion
}

// stripJSONC takes out // and /* */ comments and commas before a closing bracket, outside strings.
func stripJSONC(in []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(in))
	inStr, esc := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out.WriteByte(c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++
		case c == ',':
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\t' || in[j] == '\r' || in[j] == '\n') {
				j++
			}
			if j < len(in) && (in[j] == '}' || in[j] == ']') {
				continue
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

// ---------------------------------------------------------------- uv.lock, poetry.lock, Cargo.lock

type tomlPkg struct{ name, version, source, sourceType, sourceURL string }

// parseTomlPackages reads the [[package]] tables' top-level name, version and source (and poetry's [package.source]
// type): only lines that start a key at the beginning of the line, so a dependency array's inline tables are not
// taken for the package.
func parseTomlPackages(file string, data []byte, sink *depSink) bool {
	var pkgs []tomlPkg
	var cur *tomlPkg
	sub := ""
	saw := false
	flush := func() {
		if cur != nil {
			if len(pkgs) >= sink.max {
				sink.over = true
			} else {
				pkgs = append(pkgs, *cur)
			}
		}
		cur = nil
	}
	eachLine(data, func(line string) bool {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			return true
		}
		if t == "[[package]]" {
			flush()
			cur, sub, saw = &tomlPkg{}, "", true
			return !sink.over
		}
		if strings.HasPrefix(t, "[") && line[0] == '[' {
			switch {
			case t == "[package.source]":
				sub = "source"
			case strings.HasPrefix(t, "[package.") || strings.HasPrefix(t, "[[package."):
				sub = "other"
			default:
				flush()
				sub = ""
			}
			return !sink.over
		}
		if cur == nil || line[0] == ' ' || line[0] == '\t' {
			return true
		}
		key, val, ok := strings.Cut(t, "=")
		if !ok {
			return true
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		str := strings.Trim(val, `"'`)
		switch sub {
		case "":
			switch key {
			case "name":
				cur.name = str
			case "version":
				cur.version = str
			case "source":
				cur.source = val
			}
		case "source":
			switch key {
			case "type":
				cur.sourceType = str
			case "url":
				cur.sourceURL = str
			}
		}
		return true
	})
	flush()
	if sink.over {
		return false
	}
	if !saw {
		return true // no packages at all: a project without dependencies
	}
	for _, p := range pkgs {
		if p.name == "" || !looksVersion(p.version) {
			continue
		}
		switch file {
		case "uv.lock":
			reg, ok := tomlInlineString(p.source, "registry")
			if !ok {
				continue // the project itself, editable, path, git, url
			}
			sink.add(DepPkg{Eco: "PyPI", Name: p.name, Version: p.version, Source: registryHost(reg)})
		case "poetry.lock":
			switch p.sourceType {
			case "", "pypi":
				sink.add(DepPkg{Eco: "PyPI", Name: p.name, Version: p.version})
			case "legacy":
				src := registryHost(p.sourceURL)
				if src == "" && p.sourceURL == "" {
					src = "私有源"
				}
				sink.add(DepPkg{Eco: "PyPI", Name: p.name, Version: p.version, Source: src})
			}
		case "Cargo.lock":
			s := strings.Trim(p.source, `"`)
			if strings.HasPrefix(s, "registry+https://github.com/rust-lang/crates.io-index") || strings.HasPrefix(s, "sparse+https://index.crates.io/") {
				sink.add(DepPkg{Eco: "crates.io", Name: p.name, Version: p.version})
			}
		}
	}
	return true
}

// tomlInlineString: the string value of key in an inline table ({ registry = "https://…" }).
func tomlInlineString(table, key string) (string, bool) {
	i := strings.Index(table, key+" = \"")
	if i < 0 || !strings.HasPrefix(strings.TrimSpace(table), "{") {
		return "", false
	}
	rest := table[i+len(key)+4:]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}

// ---------------------------------------------------------------- Pipfile.lock

func parsePipfileLock(data []byte, sink *depSink) bool {
	// The indexes it names: "pypi" (or one at pypi.org) is the public one. Read before the packages are named (the
	// file may put "_meta" after them).
	type pipDep struct{ name, version, index string }
	var deps []pipDep
	indexes := map[string]string{}
	sawMeta := false
	dec := newJSONDecoder(data)
	ok := jsonObject(dec, func(key string) bool {
		switch key {
		case "_meta":
			sawMeta = true
			return jsonObject(dec, func(key string) bool {
				if key != "sources" {
					return jsonSkip(dec)
				}
				return jsonArray(dec, func() bool {
					var src struct {
						Name string `json:"name"`
						URL  string `json:"url"`
					}
					if dec.Decode(&src) != nil {
						return false
					}
					if len(indexes) >= 1000 {
						return true // more indexes than any Pipfile has: the rest are unknown, shown as their names
					}
					h := registryHost(src.URL)
					if h == "" && src.URL == "" {
						h = src.Name
					}
					indexes[src.Name] = h
					return true
				})
			})
		case "default", "develop":
			return jsonObject(dec, func(name string) bool {
				var d struct {
					Version string `json:"version"`
					Index   string `json:"index"`
				}
				if dec.Decode(&d) != nil {
					return true // not a package pinned from an index (editable, git): its value is read past
				}
				if v := strings.TrimPrefix(d.Version, "=="); looksVersion(v) {
					if len(deps) >= sink.max {
						sink.over = true
						return false
					}
					deps = append(deps, pipDep{name, v, d.Index})
				}
				return true
			})
		}
		return jsonSkip(dec)
	})
	if !ok || !sawMeta {
		return false
	}
	for _, d := range deps {
		src, known := indexes[d.index]
		if !known && d.index != "" && d.index != "pypi" {
			src = d.index
		}
		sink.add(DepPkg{Eco: "PyPI", Name: d.name, Version: d.version, Source: src})
	}
	return true
}
