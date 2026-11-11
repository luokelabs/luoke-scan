package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type scriptsHome struct {
	t    *testing.T
	root string
	l    Layout
}

func newScriptsHome(t *testing.T) *scriptsHome {
	root := t.TempDir()
	h := &scriptsHome{t, root, Layout{Root: root}}
	os.MkdirAll(h.l.Projects(), 0o755)
	return h
}

// put writes a file; a path starting with ~/ is in the home, else relative to the root.
func (h *scriptsHome) put(rel, text string) string {
	p := filepath.Join(h.root, rel)
	if strings.HasPrefix(rel, "~/") {
		p = filepath.Join(h.l.Home(), rel[2:])
	}
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *scriptsHome) dir(rel string) {
	os.MkdirAll(filepath.Join(h.l.Home(), strings.TrimPrefix(rel, "~/")), 0o755)
}

func (h *scriptsHome) run() map[string]Finding {
	ctx := h.l.Context(nil)
	f, err := NewInstallScriptsRule(&h.l, nil).Run(&ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	out := map[string]Finding{}
	for _, x := range f {
		if x.Rule != InstallScriptsRuleID || x.Verdict != Confirm || x.Category != CatPosture {
			h.t.Errorf("unexpected finding %+v", x)
		}
		if _, dup := out[x.Key]; dup {
			h.t.Errorf("two findings for %s", x.Key)
		}
		out[x.Key] = x
	}
	return out
}

func (h *scriptsHome) npm(version string) {
	h.put("usr-local/lib/node_modules/npm/package.json", `{"name":"npm","version":"`+version+`"}`)
}

func TestInstallScriptsNpm(t *testing.T) {
	cases := []struct {
		name, npmrc, version string
		want, fix            bool
	}{
		{"old npm, nothing set", "registry=https://registry.npmjs.org/\n", "11.6.2", true, true},
		{"old npm, no npmrc yet", "", "11.6.2", true, true},
		{"npm 12 blocks by default", "", "12.0.0", false, false},
		{"turned off", "ignore-scripts=true\n", "10.9.0", false, false},
		{"spaces, quotes and a comment", "  ignore-scripts = \"true\"  ; set by me\n", "10.9.0", false, false},
		{"underscore spelling", "ignore_scripts=true\n", "10.9.0", false, false},
		{"commented out", "# ignore-scripts=true\n;ignore-scripts=true\n", "10.9.0", true, true},
		{"the last one wins", "ignore-scripts=true\nignore-scripts=false\n", "10.9.0", true, false},
		{"CRLF", "registry=x\r\nignore-scripts=true\r\n", "10.9.0", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newScriptsHome(t)
			h.dir("~/.npm/_cacache")
			if c.npmrc != "" {
				h.put("~/.npmrc", c.npmrc)
			}
			h.npm(c.version)
			got, has := h.run()["npm"]
			if has != c.want {
				t.Fatalf("finding %v, want %v: %+v", has, c.want, got)
			}
			if has && (got.Evidence["append"] != "") != c.fix {
				t.Errorf("fix offered %v, want %v: %s", got.Evidence["append"] != "", c.fix, got.Evidence["how"])
			}
			if has && got.Path != filepath.Join(h.l.Home(), ".npmrc") {
				t.Errorf("path %s", got.Path)
			}
		})
	}
}

// Only a tool that is used, and only with a version found on disk: an npm nobody knows the version of is not guessed.
func TestInstallScriptsNeedsUseAndVersion(t *testing.T) {
	h := newScriptsHome(t)
	h.npm("11.0.0") // installed, never used here
	if f := h.run(); len(f) != 0 {
		t.Errorf("unused npm reported: %+v", f)
	}
	h = newScriptsHome(t)
	h.dir("~/.npm")
	if f := h.run(); len(f) != 0 {
		t.Errorf("npm of unknown version reported: %+v", f)
	}
	h.put("~/.nvm/versions/node/v20.1.0/lib/node_modules/npm/package.json", `{"version":"10.2.0"}`)
	if f := h.run()["npm"]; !strings.Contains(f.Evidence["why"], "10.2.0") || !strings.Contains(f.Evidence["why"], "~/.nvm/") {
		t.Errorf("nvm's npm: %+v", f.Evidence)
	}
}

// A project's own .npmrc is the project's: it neither counts as the user's setting nor is it read as one.
func TestInstallScriptsProjectConfigIsNotTheUsers(t *testing.T) {
	h := newScriptsHome(t)
	h.dir("~/.npm")
	h.npm("11.6.2")
	h.put("~/Projects/app/.npmrc", "ignore-scripts=true\n")
	h.put("~/Projects/app/.yarnrc.yml", "enableScripts: false\n")
	if _, has := h.run()["npm"]; !has {
		t.Error("a project's .npmrc was taken for the user's")
	}
}

func TestInstallScriptsListsPackagesWithScripts(t *testing.T) {
	h := newScriptsHome(t)
	h.dir("~/.npm")
	h.npm("11.6.2")
	h.put("~/Projects/app/package-lock.json", "{}")
	h.put("~/Projects/app/node_modules/esbuild/package.json", `{"name":"esbuild","scripts":{"postinstall":"node install.js"}}`)
	h.put("~/Projects/app/node_modules/@img/sharp/package.json", `{"name":"@img/sharp","scripts":{"install":"node install"}}`)
	h.put("~/Projects/app/node_modules/native/package.json", `{"name":"native"}`)
	h.put("~/Projects/app/node_modules/native/binding.gyp", "{}")
	h.put("~/Projects/app/node_modules/plain/package.json", `{"name":"plain","scripts":{"test":"x","prepare":"y"}}`)
	h.put("~/Projects/web/pnpm-lock.yaml", "")
	h.put("~/Projects/web/node_modules/.pnpm/core-js@3.0.0/node_modules/core-js/package.json", `{"name":"core-js","scripts":{"postinstall":"echo"}}`)
	f := h.run()["npm"]
	if f.Evidence["packages"] != "@img/sharp、esbuild、native" {
		t.Errorf("packages %q", f.Evidence["packages"])
	}
	if !strings.Contains(f.Evidence["how"], "npm rebuild @img/sharp esbuild native --ignore-scripts=false") {
		t.Errorf("how %q", f.Evidence["how"])
	}
	// Bounded: no project looked at past the limit.
	r := NewInstallScriptsRule(&h.l, nil).(*InstallScriptsRule)
	r.MaxManifests = 0
	ctx := h.l.Context(nil)
	if got := r.scriptedPackages(&ctx); len(got) != 0 {
		t.Errorf("past the bound: %v", got)
	}
}

func TestInstallScriptsLinkedConfigIsNotChanged(t *testing.T) {
	h := newScriptsHome(t)
	h.dir("~/.npm")
	h.npm("11.6.2")
	real := h.put("dotfiles/npmrc", "registry=x\n")
	os.Symlink(real, filepath.Join(h.l.Home(), ".npmrc"))
	f := h.run()["npm"]
	if f.Evidence["append"] != "" || !strings.Contains(f.Evidence["how"], "是个链接") {
		t.Errorf("linked config: %+v", f.Evidence)
	}
	os.WriteFile(real, []byte("ignore-scripts=true\n"), 0o600) // read through the link
	if _, has := h.run()["npm"]; has {
		t.Error("setting behind a link not read")
	}
}

func TestInstallScriptsPnpm(t *testing.T) {
	h := newScriptsHome(t)
	h.dir("~/Library/pnpm/store/v3")
	if f := h.run()["pnpm"]; f.Evidence["append"] != "" || !strings.Contains(f.Evidence["why"], "v3") {
		t.Errorf("old store: %+v", f)
	}
	h.dir("~/Library/pnpm/store/v10")
	if _, has := h.run()["pnpm"]; has {
		t.Error("pnpm 10 reported")
	}
	h.put("~/Library/Preferences/pnpm/config.yaml", "dangerouslyAllowAllBuilds: true # all of them\n")
	if f := h.run()["pnpm"]; !strings.Contains(f.Title, "所有依赖") {
		t.Errorf("allow-all: %+v", f)
	}
	h = newScriptsHome(t)
	h.dir("~/Library/pnpm")
	h.put("opt-homebrew/lib/node_modules/pnpm/package.json", `{"version":"9.15.0"}`)
	if f := h.run()["pnpm"]; !strings.Contains(f.Evidence["why"], "9.15.0") {
		t.Errorf("old global pnpm: %+v", f)
	}
}

func TestInstallScriptsYarn(t *testing.T) {
	h := newScriptsHome(t)
	h.put("~/.yarnrc.yml", "npmRegistryServer: \"https://registry.yarnpkg.com\"\npackageExtensions:\n  enableScripts: false\n")
	h.put("~/Projects/app/package.json", `{"name":"app","packageManager":"yarn@4.5.0+sha512.abc"}`)
	f, has := h.run()["yarn"]
	if !has || f.Evidence["append"] != "enableScripts: false" {
		t.Fatalf("old yarn (an indented key is not the top-level one): %+v", f)
	}
	h.put("~/Projects/app/package.json", `{"name":"app","packageManager":"yarn@4.14.0"}`)
	if _, has := h.run()["yarn"]; has {
		t.Error("yarn 4.14 reported")
	}
	h.put("~/.yarnrc.yml", "enableScripts: 'true'\n")
	if f := h.run()["yarn"]; f.Evidence["append"] != "" || !strings.Contains(f.Evidence["why"], "enableScripts: true") {
		t.Errorf("turned on by the user: %+v", f)
	}
	h.put("~/.yarnrc.yml", "enableScripts: false\n")
	h.put("~/Projects/app/package.json", `{"packageManager":"yarn@3.6.0"}`)
	if _, has := h.run()["yarn"]; has {
		t.Error("turned off, still reported")
	}
}

func TestInstallScriptsPip(t *testing.T) {
	h := newScriptsHome(t)
	h.dir("~/Library/Caches/pip/http")
	if _, has := h.run()["pip"]; has {
		t.Error("pip that never built anything reported")
	}
	h.put("~/Library/Caches/pip/wheels/ab/cd/Some_Pkg-1.0-py3-none-any.whl", "x")
	f, has := h.run()["pip"]
	if !has || f.Evidence["append"] == "" || !strings.Contains(f.Evidence["why"], "some-pkg") {
		t.Fatalf("pip: %+v", f)
	}
	if f.Path != filepath.Join(h.l.Home(), ".config/pip/pip.conf") {
		t.Errorf("path %s", f.Path)
	}
	for text, want := range map[string]bool{
		"[global]\nonly-binary = :all:\n":                                 false,
		"[install]\nonly_binary=:all:\n":                                  false,
		"[global]\n# only-binary = :all:\n":                               true,
		"[freeze]\nonly-binary = :all:\n":                                 true,
		"[global]\nonly-binary = :all:\n[global2]\n":                      false,
		"[global]\nonly-binary = :all:\n[install]\nonly-binary = numpy\n": true,
	} {
		h.put("~/.config/pip/pip.conf", text)
		if _, has := h.run()["pip"]; has != want {
			t.Errorf("%q: reported %v", text, has)
		}
	}
	h.put("~/.config/pip/pip.conf", "[global]\nindex-url = https://example.invalid/simple\n[freeze]\ntimeout = 10\n")
	if f := h.run()["pip"]; f.Evidence["append"] != "" {
		t.Error("one line at the end would land in [freeze]")
	}
	h.dir("~/Library/Application Support/pip")
	if f := h.run()["pip"]; f.Path != filepath.Join(h.l.Home(), "Library/Application Support/pip/pip.conf") {
		t.Errorf("macOS folder there: %s", f.Path)
	}
}

func TestInstallScriptsUv(t *testing.T) {
	h := newScriptsHome(t)
	h.dir("~/.cache/uv/wheels-v5")
	if _, has := h.run()["uv"]; has {
		t.Error("uv that never built anything reported")
	}
	h.dir("~/.cache/uv/sdists-v9/pypi/pycrypto")
	if f := h.run()["uv"]; f.Evidence["append"] != "no-build = true" {
		t.Errorf("uv: %+v", f)
	}
	h.put("~/.config/uv/uv.toml", "no-build = true # no setup.py\n")
	if _, has := h.run()["uv"]; has {
		t.Error("turned off, still reported")
	}
	h.put("~/.config/uv/uv.toml", "[pip]\nno-build = true\n")
	if f := h.run()["uv"]; f.Evidence["append"] != "" {
		t.Errorf("[pip] is uv pip only, and a line at the end lands in it: %+v", f.Evidence)
	}
}

func TestScriptsOffContent(t *testing.T) {
	for _, c := range []struct {
		tool, old string
		there     bool
		want      string
	}{
		{"npm", "", false, "ignore-scripts=true\n"},
		{"npm", "registry=x", true, "registry=x\nignore-scripts=true\n"},
		{"npm", "registry=x\n", true, "registry=x\nignore-scripts=true\n"},
		{"npm", "", true, "ignore-scripts=true\n"},
		{"npm", "ignore-scripts=false\n", true, ""},
		{"yarn", "nodeLinker: node-modules\n", true, "nodeLinker: node-modules\nenableScripts: false\n"},
		{"yarn", "enableScripts: true\n", true, ""},
		{"pip", "", false, "[global]\nonly-binary = :all:\n"},
		{"pip", "[global]\ntimeout = 5\n", true, "[global]\ntimeout = 5\nonly-binary = :all:\n"},
		{"pip", "timeout = 5\n", true, ""},
		{"pip", "[freeze]\n", true, ""},
		{"uv", "python-preference = \"managed\"\n", true, "python-preference = \"managed\"\nno-build = true\n"},
		{"uv", "[pip]\n", true, ""},
		{"pnpm", "", false, ""},
	} {
		got, ok, _ := ScriptsOffContent(c.tool, []byte(c.old), c.there)
		if ok != (c.want != "") || string(got) != c.want {
			t.Errorf("%s %q: %q %v", c.tool, c.old, got, ok)
		}
	}
}

// npm reads only keys before any [section]: a line under one turns nothing off, and no line is appended into one.
func TestInstallScriptsNpmSections(t *testing.T) {
	h := newScriptsHome(t)
	h.dir("~/.npm")
	h.npm("11.6.2")
	h.put("~/.npmrc", "registry=x\n[foo]\nignore-scripts=true\n")
	f, has := h.run()["npm"]
	if !has || f.Evidence["append"] != "" {
		t.Errorf("a line in a section counted, or a button offered: %v %+v", has, f.Evidence)
	}
	h.put("~/.npmrc", "registry=x\n[foo]\nbar=1\n")
	if f := h.run()["npm"]; f.Evidence["append"] != "" || !strings.Contains(f.Evidence["how"], "最前面") {
		t.Errorf("appended into a section: %+v", f.Evidence)
	}
	if _, ok, _ := ScriptsOffContent("npm", []byte("registry=x\n[foo]\n"), true); ok {
		t.Error("ScriptsOffContent appends into a section")
	}
}

// Several installs: which one runs is not known, so the newest is taken (an old Node.js under nvm beside npm 12 from
// Homebrew is not reported). Yarn: what the projects pin, never a version only in corepack's cache.
func TestInstallScriptsNewestVersion(t *testing.T) {
	h := newScriptsHome(t)
	h.dir("~/.npm")
	h.put("~/.nvm/versions/node/v18.0.0/lib/node_modules/npm/package.json", `{"version":"8.19.0"}`)
	h.put("opt-homebrew/lib/node_modules/npm/package.json", `{"version":"12.1.0"}`)
	if _, has := h.run()["npm"]; has {
		t.Error("old nvm npm reported beside npm 12")
	}
	h = newScriptsHome(t)
	h.dir("~/Library/pnpm")
	h.put("opt-homebrew/lib/node_modules/pnpm/package.json", `{"version":"9.0.0"}`)
	h.put("usr-local/lib/node_modules/pnpm/package.json", `{"version":"10.2.0"}`)
	if _, has := h.run()["pnpm"]; has {
		t.Error("old pnpm reported beside pnpm 10")
	}
	h = newScriptsHome(t)
	h.put("~/.yarnrc.yml", "nodeLinker: node-modules\n")
	h.dir("~/Library/Caches/node/corepack/v1/yarn/3.6.0")
	if _, has := h.run()["yarn"]; has {
		t.Error("a corepack cache alone reported")
	}
	h.put("~/Projects/a/package.json", `{"packageManager":"yarn@3.6.0"}`)
	h.put("~/Projects/b/package.json", `{"packageManager":"yarn@4.14.1"}`)
	if _, has := h.run()["yarn"]; has {
		t.Error("reported though a project uses Yarn 4.14")
	}
	h.put("~/Projects/b/package.json", `{"packageManager":"yarn@4.2.0"}`)
	if _, has := h.run()["yarn"]; !has {
		t.Error("only old Yarn pinned, not reported")
	}
}

// pip install reads [install] over [global], a later file over an earlier one; any only-binary in the way: no button.
func TestInstallScriptsPipPrecedence(t *testing.T) {
	h := newScriptsHome(t)
	h.put("~/Library/Caches/pip/wheels/a/x-1.0-py3-none-any.whl", "x")
	h.put("~/.config/pip/pip.conf", "[global]\nonly-binary = :all:\n[install]\nonly-binary = :none:\n")
	f, has := h.run()["pip"]
	if !has || f.Evidence["append"] != "" {
		t.Errorf("[install] :none: over [global] :all:: %v %+v", has, f.Evidence)
	}
	h.put("~/.pip/pip.conf", "[global]\nonly-binary = :all:\n")
	h.put("~/.config/pip/pip.conf", "[global]\nonly-binary = numpy\n")
	if _, has := h.run()["pip"]; !has {
		t.Error("a later file's value did not win")
	}
	h.put("~/.config/pip/pip.conf", "[install]\nonly-binary = :all:\n")
	h.put("~/.pip/pip.conf", "[global]\nonly-binary = :none:\n")
	if _, has := h.run()["pip"]; has {
		t.Error("[install] :all: not taken over [global]")
	}
	os.Remove(filepath.Join(h.l.Home(), ".pip/pip.conf"))
	h.put("~/.config/pip/pip.conf", "[install]\nonly-binary = :all:\n[global]\nonly-binary = :none:\n")
	if _, has := h.run()["pip"]; has {
		t.Error("[global] written after [install] taken over it")
	}
}

// The card says what else the change stops.
func TestInstallScriptsCardSaysTheCost(t *testing.T) {
	h := newScriptsHome(t)
	h.dir("~/.npm")
	h.npm("11.6.2")
	h.put("~/Library/Caches/pip/wheels/a/x-1.0-py3-none-any.whl", "x")
	h.dir("~/.cache/uv/sdists-v9/pypi/x")
	f := h.run()
	for tool, want := range map[string]string{"npm": "husky", "pip": "本地的项目", "uv": "你自己的项目照样会构建"} {
		if !strings.Contains(f[tool].Evidence["how"], want) {
			t.Errorf("%s card lacks %q: %s", tool, want, f[tool].Evidence["how"])
		}
	}
}

// Without Full Disk Access, a user config or a project linked into a folder macOS asks about is not followed: the
// tool is not judged and the report says what was left out. With it, the link is read through.
func TestInstallScriptsLinkIntoGuardedFolder(t *testing.T) {
	h := newScriptsHome(t)
	h.dir("~/.npm")
	h.npm("11.6.2")
	real := h.put("~/Documents/dotfiles/npmrc", "ignore-scripts=true\n")
	os.Symlink("Documents/dotfiles/npmrc", filepath.Join(h.l.Home(), ".npmrc")) // a relative link
	os.Symlink(filepath.Join(h.l.Home(), "Documents/proj"), filepath.Join(h.l.Projects(), "linked"))
	h.put("~/Documents/proj/package.json", `{"name":"p","packageManager":"yarn@3.6.0"}`)
	h.put("~/.yarnrc.yml", "npmRegistryServer: x\n")

	run := func(fda bool) ([]Finding, error) {
		ctx := h.l.Context(nil)
		ctx.FullDiskAccess = &fda
		return NewInstallScriptsRule(&h.l, nil).Run(&ctx)
	}
	f, err := run(false)
	sk, ok := err.(*SkippedError)
	if !ok || !strings.HasPrefix(sk.Reason, NoAccessMark) || !strings.Contains(sk.Reason, "~/.npmrc") {
		t.Fatalf("not said: %v", err)
	}
	for _, x := range append(f, sk.Partial...) {
		if x.Key == "npm" || x.Key == "yarn" {
			t.Errorf("judged without reading through the link: %+v", x)
		}
	}
	// With access the same links are followed: npm turned off there, Yarn 3 found in the linked project.
	f, err = run(true)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, x := range f {
		keys[x.Key] = true
	}
	if keys["npm"] || !keys["yarn"] {
		t.Errorf("with access: %v (%s)", keys, real)
	}

	ctx := h.l.Context(nil)
	no := false
	ctx.FullDiskAccess = &no
	for p, want := range map[string]bool{
		filepath.Join(h.l.Home(), ".npmrc"):             false,
		filepath.Join(h.l.Projects(), "linked/x"):       false,
		filepath.Join(h.l.Home(), ".yarnrc.yml"):        true,
		filepath.Join(h.l.Home(), "not-there/.npmrc"):   true,
		filepath.Join(h.l.Home(), "Documents"):          false,
		filepath.Join(h.l.Home(), "Library/Caches/pip"): true,
	} {
		if got := ctx.MayFollow(p); got != want {
			t.Errorf("MayFollow(%s) = %v", p, got)
		}
	}
}

// A link on the way to a place (~/.config into ~/Documents) or a project root that is itself a link into a guarded
// folder (~/code → ~/Documents/code) is not followed without Full Disk Access; with it, it is.
func TestInstallScriptsLinksOnTheWayIntoGuardedFolder(t *testing.T) {
	h := newScriptsHome(t)
	home := h.l.Home()
	h.dir("~/Documents/config/pnpm")
	os.Symlink(filepath.Join(home, "Documents/config"), filepath.Join(home, ".config"))
	h.put("~/Documents/code/p/package.json", `{"name":"p","packageManager":"yarn@3.6.0"}`)
	root := filepath.Join(home, "code")
	os.Symlink(filepath.Join(home, "Documents/code"), root)

	ctx := h.l.Context(nil)
	ctx.ProjectRoots = []string{root}
	r := NewInstallScriptsRule(&h.l, nil).(*InstallScriptsRule)
	no, yes := false, true

	ctx.FullDiskAccess = &no
	if got := usedBy(&ctx, home, ".config/pnpm"); got != "" {
		t.Errorf("without access, ~/.config linked into Documents was followed: %q", got)
	}
	if got := r.yarnVersions(&ctx); len(got) != 0 {
		t.Errorf("without access, a project root linked into Documents was listed: %+v", got)
	}

	ctx.FullDiskAccess = &yes
	if got := usedBy(&ctx, home, ".config/pnpm"); got != "~/.config/pnpm" {
		t.Errorf("with access the link is followed: %q", got)
	}
	if got := r.yarnVersions(&ctx); len(got) == 0 {
		t.Errorf("with access the linked project is read")
	}
}
