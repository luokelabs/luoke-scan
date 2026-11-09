package core

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// SecretsRule: credentials kept in plain text where tools put them (~/.git-credentials, ~/.netrc, tokens in ~/.npmrc…),
// and private keys, certificate bundles and cloud keys lying in Downloads, Desktop or Documents. Only small files are
// read, only their first bytes; what is reported is where and what kind, never a value.
type SecretsRule struct {
	// StrayPlaces: folders a key does not belong in, looked through two levels down.
	StrayPlaces []string
}

func init() { Register("secrets", NewSecretsRule) }

// NewSecretsRule is the same for this Mac and a fake home: it only reads the home's files.
func NewSecretsRule(l *Layout, f *Fakes) Rule {
	return &SecretsRule{StrayPlaces: []string{"Downloads", "Desktop", "Documents"}}
}

func (r *SecretsRule) ID() string      { return "secrets" }
func (r *SecretsRule) Emits() []string { return []string{"secrets.plaintext", "secrets.stray-key"} }

const secretsMaxRead = 64 << 10

// aiDecodeLossy is String(decoding:as: UTF8.self): bytes that are not UTF-8 become U+FFFD, a byte order mark stays.
func aiDecodeLossy(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return string([]rune(string(b)))
}

// aiSmallHead is the first bytes of a small regular file (not following a link, not one kept only in iCloud); ok false
// for anything else.
func aiSmallHead(path string, limit int) (string, bool) {
	st, ok := aiLstat(path)
	if !ok || !aiStReg(st) || st.Size > int64(limit) || aiDataless(st) {
		return "", false
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, int64(limit)))
	return aiDecodeLossy(data), true
}

type plaintextFound struct {
	kind  string
	count int
	how   string
}

var gitCredential = icuCS(`^[a-z][a-z0-9+.-]*://[^:/@\s]+:[^@\s]+@`)
var npmAuth = icuCS(`_(authToken|auth|password)\s*=\s*`)

// plaintextSecrets are the plain-text credentials in one of the files tools keep them in.
func plaintextSecrets(rel, text string) (plaintextFound, bool) {
	var lines []string
	for _, l := range aiSplitLines(text, true) {
		if t := aiTrimWS(l); !strings.HasPrefix(t, "#") {
			lines = append(lines, t)
		}
	}
	count := func(pred func(string) bool) int {
		n := 0
		for _, l := range lines {
			if pred(l) {
				n++
			}
		}
		return n
	}
	var p plaintextFound
	switch rel {
	case ".git-credentials":
		p = plaintextFound{"git 的账号和令牌", count(gitCredential.has), "改用钥匙串：git config --global credential.helper osxkeychain，再删掉这个文件，令牌最好换新的"}
	case ".netrc":
		// A password token with a value after it, outside comment lines.
		var words []string
		for _, l := range lines {
			for _, w := range strings.FieldsFunc(l, isWS) {
				words = append(words, w)
			}
		}
		n := 0
		for i, w := range words {
			if w == "password" && i+1 < len(words) {
				n++
			}
		}
		p = plaintextFound{"登录密码（netrc）", n, "能不用就删掉这个文件；要留着就确认只有你能读（chmod 600）"}
	case ".npmrc":
		// _authToken=${NPM_TOKEN} is the way to do it: the value is not in the file.
		p = plaintextFound{"npm 令牌", count(func(l string) bool {
			r := []rune(l)
			m := npmAuth.find(r, 0)
			if m == nil {
				return false
			}
			value := string(r[m[1]:])
			return value != "" && !strings.HasPrefix(value, "$")
		}), "令牌放进环境变量（${NPM_TOKEN}），文件里只留变量名"}
	case ".pypirc":
		p = plaintextFound{"PyPI 密码或令牌", count(func(l string) bool { return strings.HasPrefix(l, "password") }), "改用 keyring 存，删掉 password 这几行"}
	case ".docker/config.json":
		var j any
		if json.Unmarshal([]byte(text), &j) != nil {
			return p, false
		}
		top, _ := aiJSMap(j)
		auths, ok := aiJSMap(top["auths"])
		if !ok {
			return p, false
		}
		n := 0
		for _, v := range auths {
			if a, ok := aiJSMap(v); ok {
				if s, ok := a["auth"].(string); ok && s != "" {
					n++
				}
			}
		}
		p = plaintextFound{"Docker 仓库的登录", n, "在 config.json 里设 \"credsStore\": \"osxkeychain\"，重新 docker login"}
	case ".config/gh/hosts.yml":
		p = plaintextFound{"GitHub CLI 的令牌", count(func(l string) bool { return strings.HasPrefix(l, "oauth_token:") }), "gh auth logout 再 gh auth login，新版会把令牌存进钥匙串"}
	default:
		return p, false
	}
	return p, p.count > 0
}

var plaintextFiles = []string{".git-credentials", ".netrc", ".npmrc", ".pypirc", ".docker/config.json", ".config/gh/hosts.yml"}

// aiURLExt is URL's pathExtension of a path.
func aiURLExt(p string) string { return aiNSExt(filepath.Base(p)) }

// secretKeyKind is what a file in Downloads, Desktop or Documents is, if it is a key: by its first bytes, or by its name for
// a binary certificate bundle.
func secretKeyKind(path string) (string, bool) {
	ext := strings.ToLower(aiURLExt(path))
	if ext == "p12" || ext == "pfx" {
		return "证书和私钥包（" + ext + "）", true
	}
	if !(ext == "pem" || ext == "key" || ext == "json" || ext == "") && !strings.HasPrefix(filepath.Base(path), "id_") {
		return "", false
	}
	text, ok := aiSmallHead(path, secretsMaxRead)
	if !ok {
		return "", false
	}
	if strings.Contains(text, "-----BEGIN") && strings.Contains(text, "PRIVATE KEY-----") {
		return "私钥", true
	}
	if ext == "json" && strings.Contains(text, `"type": "service_account"`) && strings.Contains(text, `"private_key"`) {
		return "Google Cloud 服务账号密钥", true
	}
	return "", false
}

// aiPackageExts are folders macOS shows as one file (a package): not looked into.
var aiPackageExts = aiSet("app", "bundle", "framework", "plugin", "kext", "pkg", "mpkg", "rtfd", "xcodeproj", "xcworkspace",
	"playground", "photoslibrary", "pages", "numbers", "key", "docset", "appex", "xpc", "prefpane", "saver", "qlgenerator",
	"mdimporter", "wdgt", "component", "musiclibrary", "tvlibrary", "photolibrary", "fcpbundle", "logicx", "band", "scptd",
	"dictionary", "xcarchive", "imovielibrary", "theater", "lpdf", "oo3", "graffle", "sparsebundle", "workflow", "action")

// aiIsPackage says whether a folder is one macOS shows as one file.
func aiIsPackage(path string) bool {
	return aiPackageExts[strings.ToLower(aiURLExt(path))] && aiIsDir(path)
}

func (r *SecretsRule) Run(ctx *Context) ([]Finding, error) {
	out := []Finding{}
	for _, rel := range plaintextFiles {
		u := filepath.Join(ctx.Home, rel)
		text, ok := aiSmallHead(u, secretsMaxRead)
		if !ok {
			continue
		}
		p, ok := plaintextSecrets(rel, text)
		if !ok {
			continue
		}
		st, _ := aiLstat(u)
		others := st.Mode&0o044 != 0
		sev := Low
		if rel == ".git-credentials" || others {
			sev = Medium
		}
		title := "~/" + rel + " 里明文存着" + p.kind + "（" + strconv.Itoa(p.count) + " 个）"
		if others {
			title += "，别的用户也能读"
		}
		out = append(out, Finding{Rule: "secrets.plaintext", Category: CatPosture, Severity: sev, Verdict: Info, Path: u, Title: title,
			Evidence: map[string]string{"kind": p.kind, "count": strconv.Itoa(p.count), "how": p.how,
				"why": "能读这个文件的程序就能拿走它；备份、同步盘也会带上它"}})
	}
	var left []string
	for _, place := range r.StrayPlaces {
		if !ctx.MayLook(filepath.Join(ctx.Home, place)) {
			left = append(left, place)
		}
	}
	for _, place := range r.StrayPlaces {
		if aiContains(left, place) {
			continue
		}
		var files []string
		for _, u := range Children(filepath.Join(ctx.Home, place)) {
			if aiIsDir(u) && !aiIsPackage(u) {
				files = append(files, Children(u)...)
			} else {
				files = append(files, u)
			}
		}
		for _, u := range files {
			if ctx.IsCancelled() {
				return nil, Skip(Interrupted, out...)
			}
			kind, ok := secretKeyKind(u)
			if !ok {
				continue
			}
			out = append(out, Finding{Rule: "secrets.stray-key", Category: CatPosture, Severity: Medium, Verdict: Info, Path: u,
				Title: place + " 里有一个" + kind + "：" + filepath.Base(u),
				Evidence: map[string]string{"kind": kind,
					"why": "放在下载、桌面、文稿里的密钥容易被同步盘、备份或分享一起带走",
					"how": "还要用就挪到 ~/.ssh 或钥匙串里，只让你自己能读；不用了就删掉（先确认没有别处要用它）"}})
		}
	}
	if len(left) > 0 {
		return nil, Skip(NotLooked(strings.Join(left, "、")+" 里散落的密钥"), out...)
	}
	return out, nil
}

// ---------------------------------------------------------------- JSON as Foundation's JSONSerialization hands it over

// aiJSMap is v as a dictionary ([String: Any]).
func aiJSMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// aiJSInt is v as? Int: an integral number (true and false are 1 and 0).
func aiJSInt(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		if x == float64(int64(x)) {
			return int(x), true
		}
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// aiJSBool is v as? Bool: a boolean, or the number 0 or 1.
func aiJSBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case float64:
		if x == 0 || x == 1 {
			return x == 1, true
		}
	}
	return false, false
}

// aiJSStrings is v as? [String]: nil unless v is an array of strings only.
func aiJSStrings(v any) ([]string, bool) {
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// aiJSMaps is v as? [[String: Any]]: nil unless v is an array of dictionaries only.
func aiJSMaps(v any) ([]map[string]any, bool) {
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]map[string]any, 0, len(a))
	for _, x := range a {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, false
		}
		out = append(out, m)
	}
	return out, true
}

// aiReadJSON is a JSON file whose top is a dictionary.
func aiReadJSON(path string) (map[string]any, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return aiParseJSON(data)
}

func aiParseJSON(data []byte) (map[string]any, bool) {
	var v any
	if json.Unmarshal(data, &v) != nil {
		return nil, false
	}
	return aiJSMap(v)
}
