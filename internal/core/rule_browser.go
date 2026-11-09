package core

import (
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// BrowserRule: what browsers run beside the pages: extensions that can read and change every site, extensions
// installed by policy or not from the store, and the programs on this Mac an extension can start (native messaging
// hosts). Read from the browsers' own files; nothing is opened in a browser, and Safari's extensions are not looked at.
type BrowserRule struct {
	// Signature of a program an extension can start; nil: codesign.
	Signature func(path string) Signature
}

func init() { Register("browser", NewBrowserRule) }

// NewBrowserRule: in a fake home, what codesign says of the paths the fakes list is from them (a developer's signature
// cannot be made in a fixture); of the others it is asked.
func NewBrowserRule(l *Layout, f *Fakes) Rule {
	r := &BrowserRule{}
	if l != nil {
		r.Signature = func(path string) Signature {
			if s, ok := f.Codesign[path]; ok {
				return ParseSignature(s)
			}
			return SignatureOf(path)
		}
	}
	return r
}

func (r *BrowserRule) ID() string { return "browser" }
func (r *BrowserRule) Emits() []string {
	return []string{"browser.extensions", "browser.forced-extensions", "browser.sideloaded-extensions", "browser.native-host"}
}

// chromiumBrowsers: their user data folder under the home, and their bundle id (managed preferences).
var chromiumBrowsers = []struct{ name, path, bundleID string }{
	{"Chrome", "Library/Application Support/Google/Chrome", "com.google.Chrome"},
	{"Chrome Beta", "Library/Application Support/Google/Chrome Beta", "com.google.Chrome.beta"},
	{"Edge", "Library/Application Support/Microsoft Edge", "com.microsoft.Edge"},
	{"Brave", "Library/Application Support/BraveSoftware/Brave-Browser", "com.brave.Browser"},
	{"Arc", "Library/Application Support/Arc/User Data", "company.thebrowser.Browser"},
	{"Vivaldi", "Library/Application Support/Vivaldi", "com.vivaldi.Vivaldi"},
	{"Chromium", "Library/Application Support/Chromium", "org.chromium.Chromium"},
}

// browserEverySite: host patterns that reach every site.
var browserEverySite = aiSet("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "http://*/", "https://*/")

// extensionName is an extension's name, its message resolved when the manifest names one (__MSG_appName__).
func extensionName(manifest map[string]any, dir string) string {
	raw, ok := manifest["name"].(string)
	if !ok {
		raw = filepath.Base(filepath.Dir(dir))
	}
	if !strings.HasPrefix(raw, "__MSG_") || !strings.HasSuffix(raw, "__") {
		return raw
	}
	inner := []rune(raw)
	inner = inner[min(6, len(inner)):]
	inner = inner[:max(0, len(inner)-2)]
	key := aiLower(string(inner))
	locale, ok := manifest["default_locale"].(string)
	if !ok {
		locale = "en"
	}
	for _, l := range []string{locale, "en", "en_US"} {
		m, ok := aiReadJSON(filepath.Join(dir, "_locales", l, "messages.json"))
		if !ok {
			continue
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if aiLower(k) != key {
				continue
			}
			if e, ok := aiJSMap(m[k]); ok {
				if s, ok := e["message"].(string); ok && s != "" {
					return s
				}
			}
		}
	}
	return raw
}

// asksEverySite: whether a Chromium manifest asks for every site, in its permissions or its content scripts.
func asksEverySite(m map[string]any) bool {
	var all []any
	if p, ok := m["permissions"].([]any); ok {
		all = append(all, p...)
	}
	if p, ok := m["host_permissions"].([]any); ok {
		all = append(all, p...)
	}
	if scripts, ok := aiJSMaps(m["content_scripts"]); ok {
		for _, s := range scripts {
			if matches, ok := s["matches"].([]any); ok {
				all = append(all, matches...)
			}
		}
	}
	for _, v := range all {
		if s, ok := v.(string); ok && browserEverySite[s] {
			return true
		}
	}
	return false
}

// aiNumericCompare is NSString's compare(_:options: .numeric): runs of digits compared as numbers.
func aiNumericCompare(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	i, j := 0, 0
	isDigit := func(r rune) bool { return r >= '0' && r <= '9' }
	for i < len(ra) && j < len(rb) {
		if isDigit(ra[i]) && isDigit(rb[j]) {
			si, sj := i, j
			for i < len(ra) && isDigit(ra[i]) {
				i++
			}
			for j < len(rb) && isDigit(rb[j]) {
				j++
			}
			na := strings.TrimLeft(string(ra[si:i]), "0")
			nb := strings.TrimLeft(string(rb[sj:j]), "0")
			if len(na) != len(nb) {
				if len(na) < len(nb) {
					return -1
				}
				return 1
			}
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
			continue
		}
		if ra[i] != rb[j] {
			if ra[i] < rb[j] {
				return -1
			}
			return 1
		}
		i++
		j++
	}
	switch {
	case len(ra)-i < len(rb)-j:
		return -1
	case len(ra)-i > len(rb)-j:
		return 1
	}
	return 0
}

type browserExtension struct {
	id, name  string
	everySite bool
}

// profileExtensions: a profile's installed extensions, the newest version folder of each in Extensions.
func profileExtensions(profile string) []browserExtension {
	var out []browserExtension
	for _, e := range Children(filepath.Join(profile, "Extensions")) {
		id := filepath.Base(e)
		if graphemeCount(id) != 32 || strings.IndexFunc(id, func(r rune) bool { return r < 'a' || r > 'p' }) >= 0 {
			continue
		}
		best := ""
		for _, v := range Children(e) {
			if !Exists(filepath.Join(v, "manifest.json")) {
				continue
			}
			if best == "" || aiNumericCompare(filepath.Base(best), filepath.Base(v)) < 0 {
				best = v
			}
		}
		if best == "" {
			continue
		}
		m, ok := aiReadJSON(filepath.Join(best, "manifest.json"))
		if !ok {
			continue
		}
		out = append(out, browserExtension{id, extensionName(m, best), asksEverySite(m)})
	}
	return out
}

type extensionLocation struct {
	location int
	name     string
	hasName  bool
}

// extensionLocations: how each extension of a profile came to be installed (Chromium's location), with its name where
// the preferences keep its manifest, or its folder. From both preference files.
func extensionLocations(profile string, mayLook func(string) bool) map[string]extensionLocation {
	out := map[string]extensionLocation{}
	for _, f := range []string{"Secure Preferences", "Preferences"} {
		j, ok := aiReadJSON(filepath.Join(profile, f))
		if !ok {
			continue
		}
		exts, _ := aiJSMap(j["extensions"])
		settings, ok := aiJSMap(exts["settings"])
		if !ok {
			continue
		}
		for id, v := range settings {
			e, ok := aiJSMap(v)
			if !ok {
				continue
			}
			loc, ok := aiJSInt(e["location"])
			if !ok {
				continue
			}
			l := extensionLocation{location: loc}
			if mf, ok := aiJSMap(e["manifest"]); ok {
				l.name, l.hasName = mf["name"].(string)
			}
			if !l.hasName {
				if path, ok := e["path"].(string); ok && strings.HasPrefix(path, "/") && mayLook(path) {
					if m, ok := aiReadJSON(filepath.Join(path, "manifest.json")); ok {
						l.name, l.hasName = extensionName(m, path), true
					}
				}
			}
			if !l.hasName {
				if prev, ok := out[id]; ok && prev.hasName {
					l.name, l.hasName = prev.name, true
				}
			}
			out[id] = l
		}
	}
	return out
}

func aiUserName() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

// forcedByPolicy: extensions a policy makes the browser install (ExtensionInstallForcelist, "id;update url"), from
// the managed preferences of the Mac and of this user.
func forcedByPolicy(library, bundleID string) []string {
	if library == "" {
		return nil
	}
	var out []string
	for _, f := range []string{filepath.Join(library, "Managed Preferences", bundleID+".plist"),
		filepath.Join(library, "Managed Preferences", aiUserName(), bundleID+".plist")} {
		p := ReadPlistDict(f)
		if p == nil {
			continue
		}
		list, _ := aiJSStrings(p["ExtensionInstallForcelist"])
		for _, s := range list {
			if i := strings.Index(s, ";"); i >= 0 {
				s = s[:i]
			}
			out = append(out, s)
		}
	}
	return out
}

// nativeHostDirs: where an extension may find programs to start, with the browser's name.
func nativeHostDirs(home, library string) []struct{ browser, dir string } {
	var out []struct{ browser, dir string }
	for _, b := range chromiumBrowsers {
		out = append(out, struct{ browser, dir string }{b.name, filepath.Join(home, b.path, "NativeMessagingHosts")})
	}
	out = append(out, struct{ browser, dir string }{"Firefox", filepath.Join(home, "Library/Application Support/Mozilla/NativeMessagingHosts")})
	if library != "" {
		for _, x := range [][2]string{{"Chrome", "Google/Chrome"}, {"Edge", "Microsoft/Edge"}, {"Chromium", "Application Support/Chromium"},
			{"Brave", "Application Support/BraveSoftware/Brave-Browser"}, {"Firefox", "Application Support/Mozilla"}} {
			out = append(out, struct{ browser, dir string }{x[0] + "（所有用户）", filepath.Join(library, x[1], "NativeMessagingHosts")})
		}
	}
	return out
}

func aiFirstN(a []string, n int) []string {
	if len(a) > n {
		return a[:n]
	}
	return a
}

func (r *BrowserRule) Run(ctx *Context) ([]Finding, error) {
	out := []Finding{}
	for _, b := range chromiumBrowsers {
		root := filepath.Join(ctx.Home, b.path)
		var profiles []string
		for _, c := range Children(root) {
			if n := filepath.Base(c); n == "Default" || strings.HasPrefix(n, "Profile ") {
				profiles = append(profiles, c)
			}
		}
		sort.Strings(profiles)
		forced := aiSet(forcedByPolicy(ctx.SystemLibrary, b.bundleID)...)
		var every, policy, aside []string
		for _, p := range profiles {
			exts := profileExtensions(p)
			names := map[string]string{}
			for _, e := range exts {
				if _, ok := names[e.id]; !ok {
					names[e.id] = e.name
				}
				if e.everySite {
					every = append(every, e.name)
				}
			}
			for id, l := range extensionLocations(p, ctx.MayLook) {
				name, ok := names[id]
				if !ok {
					name = id
					if l.hasName {
						name = l.name
					}
				}
				if l.location == 7 || l.location == 9 || forced[id] {
					policy = append(policy, name)
				} else if l.location == 2 || l.location == 4 || l.location == 8 {
					aside = append(aside, name)
				}
			}
			for _, e := range exts {
				if forced[e.id] {
					policy = append(policy, e.name)
				}
			}
		}
		if n := aiSortedUnique(every); len(n) > 0 {
			list := strings.Join(aiFirstN(n, 10), "；")
			if len(n) > 10 {
				list += " 等"
			}
			out = append(out, Finding{Rule: "browser.extensions", Category: CatPosture, Severity: Low, Verdict: Info, Path: root,
				Title: b.name + " 里有 " + strconv.Itoa(len(n)) + " 个扩展能读、能改你打开的每一个网页",
				Evidence: map[string]string{"browser": b.name, "extensions": list, "why": "它们能看到你在网页上输入的密码和看的内容",
					"how": "只留认得、还在用的；在 " + b.name + " 的扩展管理页里删掉其余的，或把「网站访问权限」改成「点击时」"},
				Key: root + "|all|" + strings.Join(n, "|")})
		}
		p := aiSortedUnique(policy)
		if len(p) > 0 {
			out = append(out, Finding{Rule: "browser.forced-extensions", Category: CatPersistence, Severity: High, Verdict: Info, Path: root,
				Title: b.name + " 里有 " + strconv.Itoa(len(p)) + " 个扩展是被策略强制装上的，你自己删不掉",
				Evidence: map[string]string{"browser": b.name, "extensions": strings.Join(aiFirstN(p, 10), "；"),
					"why": "公司管的电脑上是管理员装的；自己的电脑上，这是恶意软件常用的办法（装一个描述文件，再强制装扩展）",
					"how": "不是公司电脑的话：系统设置 → 隐私与安全性 → 描述文件，删掉不认得的描述文件，再在浏览器里删掉这些扩展"},
				Key: root + "|forced|" + strings.Join(p, "|")})
		}
		var a []string
		for _, x := range aiSortedUnique(aside) {
			if !aiContains(p, x) {
				a = append(a, x)
			}
		}
		if len(a) > 0 {
			out = append(out, Finding{Rule: "browser.sideloaded-extensions", Category: CatPersistence, Severity: Medium, Verdict: Info, Path: root,
				Title: b.name + " 里有 " + strconv.Itoa(len(a)) + " 个扩展不是从扩展商店装的",
				Evidence: map[string]string{"browser": b.name, "extensions": strings.Join(aiFirstN(a, 10), "；"),
					"how": "自己开发、调试用的就留着；不认得的在 " + b.name + " 的扩展管理页里删掉"},
				Key: root + "|aside|" + strings.Join(a, "|")})
		}
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted, out...)
		}
	}
	out = append(out, r.firefox(ctx)...)
	out = append(out, r.nativeHosts(ctx)...)
	return out, nil
}

// firefox: Firefox's add-ons that can reach every site (extensions.json of each profile).
func (r *BrowserRule) firefox(ctx *Context) []Finding {
	profiles := filepath.Join(ctx.Home, "Library/Application Support/Firefox/Profiles")
	var names []string
	for _, p := range Children(profiles) {
		j, ok := aiReadJSON(filepath.Join(p, "extensions.json"))
		if !ok {
			continue
		}
		addons, ok := aiJSMaps(j["addons"])
		if !ok {
			continue
		}
		for _, a := range addons {
			if t, _ := a["type"].(string); t != "extension" {
				continue
			}
			if l, _ := a["location"].(string); l != "app-profile" {
				continue
			}
			if active, ok := aiJSBool(a["active"]); ok && !active {
				continue
			}
			perms, _ := aiJSMap(a["userPermissions"])
			origins, _ := aiJSStrings(perms["origins"])
			any := false
			for _, o := range origins {
				if browserEverySite[o] {
					any = true
				}
			}
			if !any {
				continue
			}
			loc, _ := aiJSMap(a["defaultLocale"])
			if n, ok := loc["name"].(string); ok {
				names = append(names, n)
			} else if id, ok := a["id"].(string); ok {
				names = append(names, id)
			} else {
				names = append(names, "?")
			}
		}
	}
	n := aiSortedUnique(names)
	if len(n) == 0 {
		return nil
	}
	return []Finding{{Rule: "browser.extensions", Category: CatPosture, Severity: Low, Verdict: Info, Path: profiles,
		Title: "Firefox 里有 " + strconv.Itoa(len(n)) + " 个扩展能读、能改你打开的每一个网页",
		Evidence: map[string]string{"browser": "Firefox", "extensions": strings.Join(aiFirstN(n, 10), "；"),
			"why": "它们能看到你在网页上输入的密码和看的内容", "how": "只留认得、还在用的；在 Firefox 的「附加组件」里删掉其余的"},
		Key: profiles + "|all|" + strings.Join(n, "|")}}
}

// nativeHosts: programs an extension can start on this Mac, reported when nobody vouches for them or they are gone:
// one finding for a program however many browsers register it.
func (r *BrowserRule) nativeHosts(ctx *Context) []Finding {
	type host struct {
		name, program   string
		browsers, files []string
	}
	hosts := map[string]*host{}
	for _, d := range nativeHostDirs(ctx.Home, ctx.SystemLibrary) {
		var jsons []string
		for _, u := range Children(d.dir) {
			if aiURLExt(u) == "json" {
				jsons = append(jsons, u)
			}
		}
		sort.Strings(jsons)
		for _, u := range jsons {
			text, ok := aiSmallHead(u, secretsMaxRead)
			if !ok {
				continue
			}
			j, ok := aiParseJSON([]byte(text))
			if !ok {
				continue
			}
			program, ok := j["path"].(string)
			if !ok {
				continue
			}
			name, ok := j["name"].(string)
			if !ok {
				name = strings.TrimSuffix(filepath.Base(u), "."+aiURLExt(u))
			}
			k := name + "\n" + program
			h := hosts[k]
			if h == nil {
				h = &host{name: name, program: program}
				hosts[k] = h
			}
			if !aiContains(h.browsers, d.browser) {
				h.browsers = append(h.browsers, d.browser)
			}
			h.files = append(h.files, u)
		}
	}
	keys := make([]string, 0, len(hosts))
	for k := range hosts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	signature := r.Signature
	if signature == nil {
		signature = SignatureOf
	}
	var out []Finding
	for _, k := range keys {
		h := hosts[k]
		// In a guarded folder without Full Disk Access: not read, and reason enough to say.
		sig := Signature{Kind: SigUnknown}
		if ctx.MayLook(h.program) {
			sig = signature(h.program)
		}
		if !(sig.Unvouched() || sig.Kind == SigInvalid || sig.Kind == SigMissing || sig.Kind == SigUnknown) {
			continue
		}
		many := len(h.files) > 1
		these := "这个"
		if many {
			these = "这些"
		}
		// A browser's own folder and its folder for all users are one browser.
		var bs []string
		for _, b := range h.browsers {
			bs = append(bs, strings.ReplaceAll(b, "（所有用户）", ""))
		}
		browsers := len(aiSortedUnique(bs))
		how := "认得就留着（有的工具自己编的就没签名）；不认得的删掉" + these + "登记文件"
		if sig.Kind == SigMissing {
			how = "程序已经删了，" + these + "登记文件也可以删掉"
		}
		ev := map[string]string{"program": h.program, "signature": sig.Label(), "browsers": strings.Join(h.browsers, "、"),
			"why": "登记在这里的程序，扩展一叫就会以你的身份运行", "how": how}
		if many {
			ev["files"] = strings.Join(h.files, "\n")
		}
		title := "浏览器扩展能启动的本机程序 " + h.name + " 没有开发者担保（" + sig.Label() + "）"
		sev := Medium
		if sig.Kind == SigMissing {
			title = "浏览器扩展能启动的本机程序 " + h.name + " 已经不在了"
			sev = Low
		}
		if browsers > 1 {
			title += "（" + strconv.Itoa(browsers) + " 个浏览器里登记着）"
		}
		files := append([]string{}, h.files...)
		sort.Strings(files)
		out = append(out, Finding{Rule: "browser.native-host", Category: CatPersistence, Severity: sev, Verdict: Info, Path: h.files[0],
			Title: title, Evidence: ev,
			// The program and the files that register it: pointed at another program, it is another finding.
			Key: "native-host|" + h.program + "|" + strings.Join(files, "|")})
	}
	return out
}
