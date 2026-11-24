# 查依赖的安装脚本

11-06 开始做。这一份说规则 `deps.install-script`：查哪里、查什么、怎么定、上限、隐私，以及量误报的结果。恶意包名单是另一条规则，这里不管。

## 为什么查

`npm install` 装一个包时，会自动运行它 `package.json` 里的 `preinstall`、`install`、`postinstall`，用的是你的权限：能读 `~/.npmrc`、`~/.ssh`、`~/.aws`，能联网，能往 LaunchAgents 里放东西。近几年 npm 上被投毒的包几乎都是靠这一步：装上就把令牌发出去、下载程序来运行、拿你的 GitHub 令牌往仓库里推工作流、再用你的 npm 令牌发布被改过的包。名单只认得已经被报过的，这条规则按做法认。

## 查哪些地方

- **项目的依赖**：本工具已经认的项目目录（`~/Developer`、`~/Projects`、`~/Documents/GitHub` 这些，和 `stale.project`、skill 同一份）下的每个项目，每个项目目录最多 500 个项目。在项目里往下最多 4 层、最多看 400 个文件夹找 `node_modules`（monorepo 一个包一个），不进隐藏文件夹、链接和 `node_modules` 本身。
- **全局装的 npm 包**：`/opt/homebrew/lib/node_modules`、`/usr/local/lib/node_modules`、`~/.npm-global/lib/node_modules`、`~/.npm-packages/lib/node_modules`、nvm 的每个 node 版本（`~/.nvm/versions/node/*/lib/node_modules`）、Volta 的（`~/.volta/tools/image/node/*/lib/node_modules`）。
- 一个 `node_modules` 里认的包：它下面的文件夹、`@scope/` 下的文件夹、pnpm 的仓库（`.pnpm/<包>@<版本>/node_modules/<包>`），以及包里再嵌一层的 `node_modules`（npm 装冲突版本的地方）。链接不跟（pnpm 的链接指回它的仓库，那里已经看了）。
- **从源码装的 Python 包**：项目虚拟环境（`.venv`、`venv`、`env`，有 `pyvenv.cfg` 的）的 `src/` 下，`pip install -e git+…` 拉下来的每个包的 `setup.py`。**不看 site-packages**：装在那里的是装好了的，`setup.py` 已经跑过、也不在那里。
- 项目自己的 `package.json` 不看：那是你自己的代码。

## 读什么

**只读安装脚本，不扫整个 `node_modules`**：每个包只 stat 它的 `package.json`；新的或变了的才读，取出名字、版本和三个钩子。照 npm 的读法读：键名大小写要一样（`SCRIPTS` 不算 `scripts`），同一个键写两遍取后一个，开头的 BOM 去掉；读不出来的（npm 也装不了）记下，没变不再读；嵌套超过 1 万层的（Go 的 JSON 读不了，npm 读得了、照样跑钩子）读不出钩子，每一轮都算进 partial。钩子的命令本身查一遍（npm 用 `sh -c` 跑钩子，命令里的每一行各算一条，`#` 到行尾是注释），再跟到它运行的文件：

| 钩子里写的 | 跟到 |
|---|---|
| `node install.js`、`node ./scripts/postinstall` | 包里的那个文件（照 node 的找法补 `.js`、`.cjs`、`.mjs`、`/index.js`） |
| `node -r ./x.js …`、`--require=./x.js`、`--import ./x.mjs`、`NODE_OPTIONS='--require ./x.js' node-gyp rebuild` | node 先载入的那个文件 |
| `sh -c '…'` | 里面的命令 |
| 前面的 `nohup`、`time`、`command`、`then`、`do`、`{`、`!`、`env`、`cross-env`、`FOO=1` | 跳过，看后面的命令 |
| `node -e "try{require('./postinstall')}catch(e){}"` | 它 require 的包里的文件（core-js、nx、vue-demi 都这样写） |
| `sh ./setup.sh`、`sh -e x.sh`、`bash -eu -o pipefail ./y.sh`、`python3 build.py`、`./bin/postinstall` | 包里的那个文件（shell 的 `-e`、`-x`、`-o …`、`--` 是选项，后面的才是文件；`-c`、`-ec` 是命令） |
| `npm run build`、`yarn setup` | 那个脚本的命令，再跟一层 |
| `node-gyp rebuild`、`prebuild-install`、`node-pre-gyp install`、`husky install`、`patch-package` | 不跟：这些是别的工具，不是这个包自己的代码（`binding.gyp` 是构建配置，不是脚本） |

只跟包里的普通文件：绝对路径、`..` 出去的、经过链接的、带变量的都不跟。被跟到的文件不再顺着它的 `require` 往下找。

## 查什么

用 skill 检查的那套规则（`skillcheck.go`，见 [skills.md](skills.md)），再加几条只对安装脚本有意义的（`installscript.go`）。安装脚本没人读、每装一次就跑一次，所以**只报安装脚本不该做的事**，常见的正经做法一律不报：编译原生模块、下载自己的预编译程序（esbuild、sharp、puppeteer、playwright、electron 这类）、打印求赞助的横幅、装 git 钩子。

| 报的 | 怎么认 |
|---|---|
| 读密钥再发出去 | 同一个文件里读了 SSH 私钥、AWS、gcloud、kube、docker、gh、netrc 的凭证、AI 工具的登录凭证、钥匙串、浏览器的密码和 Cookie、加密钱包、`~/.npmrc`、`~/.pypirc`，又往外发了数据（POST、上传、`https.request`、socket、DNS 查询）；环境变量里的令牌（`NPM_TOKEN`、`GITHUB_TOKEN`……）只在发到专门收数据的网站时才算（拿 `GITHUB_TOKEN` 去 GitHub 下载是正经用法） |
| 单独读密钥 | 上面那些凭证（环境变量和项目里的 `.env` 除外）单独读了也报 |
| 把用户名、主机名发出去 | `os.hostname()`、`os.userInfo()`、`whoami` 和往外发、DNS 查询在同一个文件：依赖混淆的探测 |
| 发到专门收数据的网站、临时隧道、贴文本网站 | 同 skill |
| 下载就运行 | `curl … \| sh`、`wget -O- \| bash`、`bash <(curl …)`、`eval "$(curl …)"`；`exec`/`eval` 网上取来的代码；下载程序再加执行权限（核对了校验和的不算）；官方安装脚本（rustup、Homebrew……）不算 |
| 解开编码直接运行 | `eval(Buffer.from(…,'base64'))`、`new Function(atob(…))`、`exec(base64.b64decode(…))`、`execSync(Buffer.from(…))`；一大段编码（≥ 120 个字符）和 `node -e`、`python -c`、`eval`、`Function`、`exec`、`spawn`、`vm` 在同一行。编码解得开的，解出来的也照查一遍，查到的标「藏在编码里」 |
| 跑找密钥的工具 | trufflehog、gitleaks、detect-secrets、ggshield、noseyparker |
| 往代码仓库里推 GitHub Actions 工作流 | 提到 `.github/workflows` |
| 用你的令牌建仓库、发布包 | 调 GitHub 建仓库、登记自托管运行器；`npm publish`、建 npm 令牌（会传到你发布的包里） |
| 让东西自己启动 | 往 LaunchAgents 里写、`launchctl load`、改 crontab、往 shell 的启动文件里写（只加 PATH 的不算）、往 `authorized_keys` 里加钥匙 |
| 改 AI 工具 | 写 AI 工具的设置、记忆，用 `--dangerously-skip-permissions`、`--yolo` 让它跳过确认 |
| 关保护、大面积删除、反弹 shell | 同 skill（去隔离标记除外：下载预编译程序的安装脚本有时会去掉自己下载的程序的隔离标记） |

注释里的、讲这些事的（列出要查什么的规则、正则）不算，但两样都按文件的语言、按语句认：

- **什么是注释**按文件的语言（扩展名，没有就看 `#!` 那一行，都没有就是 sh 的）：JavaScript 只认 `//` 和 `/* … */`，以 `*` 开头的行只有在一行开头打开的 `/*` 里面才算注释（不然是接着上一行的乘法：`x = 2` 下一行 `* run()`），`#`、`REM`、`--` 开头的是代码；sh 和 Python 只认 `#`（`* ; curl … | sh`、`-- ; …` 是命令）。一行开头是注释、同一行里关上了（`/**/ x`、`/*! 许可证 */ x`）的，后面的代码照查（skill 的检查也一样，它的评测结果没变）。
- **讲这些事**只认写成匹配规则的：命中的字在 JS 的正则字面量（`/…/`）里，或者在直接交给正则的字符串里（`RegExp(`、`re.compile(`、`re.search(` 这类）。词一律不算，在哪都不算：变量名叫 `flags`、同一个字符串里写 `never` 或正则的 `\s`、另一条语句里的 `malicious`，都是安装脚本加一个词就能把命令藏起来的写法（`const s = 'curl … | sh # never'; execSync(s)`）。注释先去掉，注释里的不算匹配规则。
- `| sh` 后面跟注释（`curl … | sh # …`）也算下载就运行（skill 的检查也一样）。

脚本一行一行读，另有两样和 skill 的检查共用（`skillcommands.go`，见 [skills.md](skills.md)「怎么读脚本」）：

- **续行**：行尾用 `\` 接到下一行的命令（shell 的命令、钩子里的几行、JavaScript 和 Python 里跨行的字符串），除了一行一行读，再接成一行读一遍（`installReadings`）：`curl … \` 换行 `| sh` 照报，行号是这条命令开始的那一行。两遍查到的合在一起，各行自己查得到的不会少。整行是注释的不往下接。钩子里跟到哪个文件也这样读（`node \` 换行 `evil.js`）。
- **管道按段看**：前面一段是下载或解码，后面任何一段最终跑的是 shell 或解释器就算下载就运行，隔着 `xargs`、`env`、`nohup`、`timeout`、`sudo` 这类包装也算：`curl … | xargs -I{} bash -c "{}"`、`| env X=1 sh`、`| nohup timeout 60 bash -s`。shell 的安装脚本、钩子的命令、JavaScript 和 Python 交给 `exec`、`os.system` 的字符串里（`execSync("curl … | xargs sh")`）都查。后面的段不跑进来的内容的不算（`| xargs rm -f`、`| xargs grep`、`| tar xz`、`| xargs -n1 python3 check.py`、`| jq .`）；官方安装脚本隔着包装也还是官方安装脚本，不报。在正则字面量和交给正则的字符串里的照旧不算。

脚本里有不合 UTF-8 的字节或 NUL 也照查（node 照样运行这种文件）：坏字节换成替换字符，NUL 当空格。不查的只有钩子**自己运行**（`./bin/x`）、开头真是程序（Mach-O、ELF 的开头，而且前 80 个字节里第一个换行之前有 NUL：系统运行不了的文件会交给 sh 当脚本跑，bash 只在看到这个时才拒绝）的文件；只是开头像程序的（`\xCF\xFA\xED\xFE` 后面跟一行命令）照查，经 `sh`、`node` 跑的不管开头是什么都照查。压缩过的代码（一行几千字）按语句切成小段再查，行号照原来的。

## 发现长什么样

- 一个包、一个版本、查到的一样的合成一条，几个项目里都有就都列上。规则 `deps.install-script`，类别 `malware`，**要确认**（中），不是急事：规则会看错。名单认出来的才当急事，那是另一条规则。
- 标题：「项目 app 的依赖 pkg@1.2.3 安装时会把 npm 的登录令牌（~/.npmrc）发出去」「全局装的 npm 包 g@9.9.9 安装时会在 LaunchAgents 里放东西（开机自己运行）」「项目 app 里从源码装的 Python 包 helper 装的时候会把 AWS 的凭证发出去」；查到不止一种时加「，另有 N 处要看」。
- 依据：`dependency`（包名和版本）、`where`（哪些项目，或全局）、`hook`（哪个钩子）、`files`（哪些文件）、`kinds`、`why`（查到什么，每一条写哪个文件第几行，用固定的话说，不写网址、域名、IP 和命令原文）、`how`（先别再装依赖，看看这个版本有没有被报过，装过的话换掉可能被读过的令牌，看看自己启动的东西有没有多出来）。
- 包名用 npm 装它的文件夹（`node_modules/@scope/name`），不用 `package.json` 里写的（冒名的包可以写成任何名字）；两者对不上时依据里加一句 `name`。文件夹名不合 npm 的规矩就写「一个名字不合规矩的包」；版本不像版本号就不写。
- 文件名只在明明白白是脚本路径时显示（字母、数字、`_`、`-`，每段最多一个点，最后一段是脚本的扩展名），否则写「钩子运行的一个脚本」：文件名是包自己起的，可以写成网址或给模型的话。
- 不出清理方案：删依赖、换版本由你自己做。
- 不交给本机模型讲解（`ExplainAsks` 把它排除，和 skill 的发现一样）：标题和依据里有包自己定的东西（名字、版本），不让它们到模型那里。以后要讲解，再像 skill 那样单独设计。

## 上限

| | 上限 | 超了怎么办 |
|---|---|---|
| 每个项目目录的项目 | 500 个 | 后面的不看 |
| 项目里找 `node_modules` | 4 层、400 个文件夹 | 记一条 `deps.install-script.partial`（仅供参考） |
| 每轮的包 | 40000 个 | 同上 |
| 单个 `package.json` | 1 MB | 不读，算进 partial |
| `package.json` 的嵌套 | 1 万层 | 读不出钩子，每轮算进 partial |
| 单个脚本 | 1 MB | 同上 |
| 每轮新读的 | 16 MB | 同上，下一轮再读 |

检查半兆的脚本不到一秒（压缩代码、一行一条命中，几种最坏的写法都量过；原来命中多时随命中数的平方涨，半兆要近一分钟），常见的安装脚本是几 KB；读过的、没变的不再读。查一个文件时也看这一轮有没有被打断（用户回来了）：被打断就停下，查了一半的文件不记，下一轮重读。

## 同一个文件只看一次

照病毒扫描的规矩（`malware_scanned`）：每个读过的 `package.json` 和脚本记下 inode、大小、修改时间、inode 的改动时间（ctime：把修改时间改回去也藏不住）和规则的版本（`install_scripts_scanned` 表，在数据目录里），还有查到了什么（`package.json` 只记名字、版本、有哪些钩子、在第几行、跟到哪些文件，**不记命令原文**；脚本只记查到的几条固定的话和行号）。下一轮这几样都没变就不再读，直接用记下的；规则改了（`installRulesVersion` 或规则包的版本变了）全部重读。不在了的忘掉；没有完全磁盘访问时没看的地方，记下的留着。被打断时读过的照样记下，下一轮接着读。

## 完全磁盘访问

没有完全磁盘访问时，文稿、桌面、下载里的项目不看（看了 macOS 会弹框），整条规则记成「没看」，别处查到的照报，和 skill 一样。全局的那几个文件夹不受影响。

## 量误报

**正经的**：

- 单元测试里一套照常见包写的安装脚本（`installBenign`，自己写的，照它们做的事）：预编译程序的下载（esbuild 那样，带 `chmodSync`）、往 `~/.cache` 下载浏览器（puppeteer 那样，带 `https.request`）、求赞助的横幅（core-js）、原生模块失败了再编译、带 `GITHUB_TOKEN` 下载又发一条只有平台信息的统计（prisma 那样）、sass 的绑定下载、装 git 钩子（husky、lefthook）、编译 C 库的 shell 脚本、按时区打印的话（es5-ext）、下载头文件再用 cmake 编译的 `setup.py`、只提示怎么加补全的、核对校验和再加执行权限的、一个变量叫 `hostname` 的网络客户端，和 16 种常见的钩子写法：一条都不报。
- 真实的包（11-06）：在临时目录里给 104 个常见的、带安装脚本或依赖带安装脚本的包（esbuild、sharp、puppeteer、playwright、electron、core-js、husky、bcrypt、sqlite3、canvas、node-sass、@swc/core、cypress、prisma、nx、@sentry/cli、chromedriver、@vscode/ripgrep、node-pty、ngrok、yarn、workerd、wrangler、turbo、@biomejs/biome、next、vite……）各建一个项目，`npm install --ignore-scripts`（**没有运行任何安装脚本**）。一共 3322 个不同的包和版本，70 个带安装钩子，跟到 49 个不同的脚本文件：**0 条发现**。第一轮 1.4–7 秒，第二轮什么都没变 0.2–0.4 秒、一个文件都不读。
- 从这些 `node_modules` 里每 40 个挑一个普通的 `.js`（1–60 KB，1336 个，不是安装脚本、规则平时不看）硬查一遍，看规则本身有多吵：3 个会报（ssh2 测试里读主机钥匙、一个 AWS 客户端读凭证再发请求；第三个是变量名 `hostname`，已经改掉）。

**恶意的**（`installMalicious`，都是自己照公开的事故报告写的样子，没有下载真的恶意代码）：读 `~/.npmrc` 再 POST、读 SSH 私钥和 AWS 凭证发到聊天机器人、依赖混淆的探测（用户名主机名经 DNS、经 POST 发到收数据的网站）、`curl | bash`、`execSync` 里的 `wget | sh`、`eval(Buffer.from(…))`、`execSync(Buffer.from(…))`、`node -e` 带一大段编码、`python -c` 带一大段编码、编码里藏的 `curl | bash`、跑 trufflehog、写 `.github/workflows`、调 GitHub 建仓库、`npm publish`、写 LaunchAgent 再 `launchctl load`、往 `~/.zshrc` 里加关机命令、改 crontab、拷浏览器的 Login Data 和钱包、让 AI 工具跳过确认、反弹 shell、下载程序加执行权限再运行、`setup.py` 读 AWS 凭证再 POST、`setup.py` 里 `curl | sh`、环境变量里的令牌发到收数据的网站、全部环境变量发出去、压缩代码中间夹着 `curl | sh`：27 个都认出来。

## 看不到的

- 被跟到的文件再 `require` 的别的文件；钩子运行的是编译过的程序；超过 1 MB 的脚本（真实的投毒包有把几 MB 的打包代码放在 `postinstall` 里的：这类只算进 partial）。
- 加密的载荷（用包的描述当钥匙解开再运行这类）：只有「一大段编码和运行代码在同一行」能认出来。
- 把命令写成正则字面量再取出来运行（`execSync(/curl … | sh/.source)` 这类）：正则里的字一律当成在讲这件事。
- 一条命令拆在几个字符串里拼起来的（`'curl … | ' + 'sh'`、Python 里相邻的两个字符串）；不用行尾的 `\` 而靠括号、引号跨行的命令：只按各行查。
- 不经安装钩子、在被 `require` 时才跑的恶意代码：那是名单和病毒扫描的事。
- Yarn PnP 的 zip 缓存、Bun 的全局包：还没看。
- 以后再做：钩子里用 perl、ruby 跑的文件；`node .`（跑 `package.json` 的 `main`）；没写 `install` 时 npm 对有 `binding.gyp` 的包自动跑的 `node-gyp rebuild`（构建配置里能带命令）；git 依赖装的时候跑的 `prepare`。
- YARA：这些规则要的是「同一个文件里读了 A 又做了 B」和「这一行不是在讲这件事」，用 Go 和 skill 共用一套更合适；病毒扫描那边的 YARA 规则照旧扫下载来的文件。
