# 查本机装的 AI skill

11-02 开始做。这一份说静态检查（规则 `skill`）：查哪里、查什么、怎么定轻重、隐私、看不到什么，以及之后的语义检查打算怎么接。

## 为什么查

skill 是 AI 工具（Claude Code、Cursor、Gemini CLI、Codex……）照着做事的说明书：一个文件夹，里面一份 `SKILL.md`（开头是 YAML，至少有 `name`、`description`，可以有 `allowed-tools`；后面是给 AI 的说明），常常还带脚本。AI 用它时会照着说明做、运行它带的脚本，用的是你的权限：能读你能读的文件、能联网、能改设置。装一个来路不明的 skill，和运行一个来路不明的脚本差不多，而且它还能用文字指使 AI。

## 查哪些地方

一张表（`SkillPlaces`，`internal/core/skill.go`），以后和规则、缓存的清单一起挪进数据文件，让社区也能增改（在计划中）。各家工具和各种说法对这些位置不完全一致，表要好加；没有的文件夹直接跳过。

| 谁的 | 个人（家目录下） | 项目里 |
|---|---|---|
| Claude Code | `~/.claude/skills` | `.claude/skills` |
| Claude Code 的插件 | `~/.claude/plugins` 往下最多 7 层找 `SKILL.md` | |
| Cursor | `~/.cursor/skills` | `.cursor/skills` |
| Gemini CLI | `~/.gemini/skills` | `.gemini/skills` |
| GitHub Copilot | `~/.copilot/skills` | `.github/skills` |
| Codex | `~/.codex/skills`（含 `.system` 这类分组，往下 3 层） | `.codex/skills` |
| 几个工具共用 | `~/.agents/skills` | `.agents/skills` |

- 项目：本工具已经认的项目目录（`ctx.projectRoots`：`~/Developer`、`~/Projects`、`~/Documents/GitHub` 这些）下面的每个项目，每个项目目录最多看 500 个项目。
- 一个有 `SKILL.md` 的文件夹就是一个 skill；它里面的文件夹归它，不再往下找别的 skill。
- 链到别处的 skill 文件夹（常见：从自己的 dotfiles 仓库链过来）照看，一步一步核对能不能看；同一个真实位置只算一次。
- **没有完全磁盘访问**：文稿、桌面、下载里的项目不看（看了 macOS 会弹框），报「没看」，和别的规则一样进「要完全磁盘访问」那一项；链接指进这些地方的也一样。

## 怎么读

`Skill`（`internal/core/skill.go`）把一个 skill 读成一个值：哪个工具、个人还是项目、文件夹（找到时的样子和链接解开后的真实位置）、名字、说明、`allowed-tools`、`SKILL.md` 里的其他字段、说明正文（和它从第几行开始）、每个文件（相对路径、大小、种类、文字内容），以及一个内容哈希。

文件的种类按文件名和开头的字节分：文字、脚本（`.sh`、`.py`、`.js`……，或 `#!` 开头）、编译过的程序（Mach-O、ELF、`.pyc`、`.so`/`.dylib`、`.jar`、`.class`、`.wasm`、编译过的 AppleScript……）、压缩包（zip、tar、gzip、xz、7z、磁盘映像、安装包……）、认不出的二进制、其他（图片、字体、PDF、Office 文档：AI 不运行它们）。

上限（`Skills.Limits`）：

| | 上限 | 超了怎么办 |
|---|---|---|
| 每轮 skill | 200 个 | 记一条 `skill.partial`（低），说多少个没查 |
| 每个 skill 的文件 | 300 个（看过的条目 5000 个） | 没列的计数，算「读不了」 |
| 单个文字文件 | 512 KB | 不读，算「读不了」 |
| 每个 skill / 每轮读的字节 | 4 MB / 64 MB | 后面的不读，算「读不了」 |
| 文件夹层数 | 8 层 | 更深的不进，算「读不了」 |

- **不跟着链接出 skill 的文件夹**：链接指向文件夹里面的，按它指的那个文件看；指到外面的不跟（只读链接本身，不碰另一头），记下来，算「读不了」。
- `node_modules`、Python 虚拟环境（有 `pyvenv.cfg` 的文件夹）、`site-packages` 不逐个看，算「读不了」（低）。
- Python 自己留下的 `__pycache__/x.cpython-312.pyc`，旁边有 `x.py` 的，看 `x.py` 就够了，不算编译过的程序。
- 只在 iCloud 里、没下载到这台 Mac 的文件不读（读了会触发下载）。

## 十类检查

都写在 `internal/core/skillcheck.go`（Go 的正则没有前后查找，原样照 ICU 的写法跑在 `skillre.go` 的小匹配器上）。一行一行看说明和脚本；有几类要把同一个文件里的几处合起来看。

| 类（规则名） | 查什么 | 轻重 |
|---|---|---|
| 读密钥再往外发（`skill.exfil`） | 读 `~/.ssh` 里的私钥（按文件名，或把整个文件夹打包、拷走）、`~/.aws` 的凭证、gh 的令牌、`.netrc`、`.git-credentials`、云和容器的登录、AI 工具自己的登录凭证、钥匙串（`dump-keychain`、`find-internet-password`、浏览器的 Safe Storage）、浏览器的密码和 Cookie 数据库、加密货币钱包和助记词、信息和邮件的数据库、整个环境变量；往外发（curl 带数据或上传、wget 发数据、nc、Python 和 Node 的 POST、scp/rsync 到别的机器、发邮件、传 Gist、socket）；常被用来收数据的地方（收 webhook 的网站、临时隧道、贴文本和传文件的网站、聊天机器人的收消息地址、直接写的公网 IP） | 读和发在同一个脚本里（说明里在 3 行以内）：高。只读：钥匙串、浏览器、钱包、私人数据、AI 工具凭证为中，别的不单独报。只发：不报；发到收数据的网站、隧道、贴文本网站为中，聊天机器人和 IP 为低。`.env`、钥匙串里的单独一项（skill 拿自己的 API key 的常见做法）只有和收数据的地方在一起才算 |
| 下载直接运行（`skill.download-exec`） | `curl … \| sh/bash/python/…`、`bash <(curl …)`、`sh -c "$(curl …)"`、`eval "$(curl …)"`、`base64 -d \| sh`、Python 的 `exec(b64decode(…))`、`exec(urlopen(…))`、JS 的 `eval(atob(…))`；下载到文件再 `chmod +x` 同一个文件 | 高；下载加执行权限、文件里核对了校验和或签名的，降成中（算供应链）；官方安装脚本（rustup、uv、Homebrew 这类，表在 `officialInstaller`）低 |
| 提权和关保护（`skill.escalation`） | `sudo`（低；Linux 装包的 `sudo apt-get` 这类不算）；把密码喂给 `sudo -S`、`with administrator privileges`、改隐私权限数据库（TCC.db 的写语句）、去掉隔离标记（`xattr -d/-c`）、`spctl --master-disable`、`csrutil disable`、关 LSQuarantine、关防火墙、改 sudoers、把账户加进管理员组、改启动参数 | 高；只提到 TCC、`tccutil reset` 为中 |
| 自启动（`skill.persistence`） | 往 `~/Library/LaunchAgents`（`LaunchDaemons`）里写（只用文字说的低一档）、`launchctl load/bootstrap/enable`、改 crontab、往 shell 的启动文件（`.zshrc`、`.bash_profile`……）里写、AppleScript 加登录项、往 `~/.ssh/authorized_keys` 里加钥匙、系统的定时任务和启动脚本 | 高；往启动文件里只加 PATH、alias、工具自己的 `eval "$(x init)"` 为低；`launchctl kickstart`、注册后台程序的 API 为中 |
| 改 AI 自己（`skill.agent-tamper`） | 往 AI 工具的设置里写（只用文字说的为中）（`~/.claude/settings.json` 的钩子、各家的 MCP 设置、Codex 的 `config.toml`……）、写 AI 的记忆和长期指令（`CLAUDE.md`、`AGENTS.md`、`GEMINI.md`、`.cursorrules`……）、写别的 skill（写 `SKILL.md`，或用通配符写一批；装自己不算）；让 AI 工具跳过确认（`--dangerously-skip-permissions` 这类） | 高；它的名字或说明就说自己是做这个的（写 skill 的 skill、配钩子的 skill、生成 CLAUDE.md 的 skill），降成低并注明；跳过确认为中 |
| 大面积删除（`skill.destructive`） | `rm -rf` 家目录、根目录、`/Users`、`/System`、`/Library`、`/Applications`、家目录下的文稿/桌面/下载/图片……；`find ~ … -delete`（`.DS_Store`、`*.pyc` 这类除外）；`diskutil erase…`、`dd of=/dev/disk…`、`mkfs`；Python、Node 删家目录或根目录 | 高 |
| 给 AI 的话（`skill.injection`） | 让 AI 忽略原来的指令（中英文）；冒充系统、开发者（各家聊天模板的记号，按写法认、不按名单：`<\|im_start\|>system`、`<\|turn>`、`<start_of_turn>`、`<tool_response>`、`[INST]`、`[SYSTEM_PROMPT]`、`<｜User｜>`；`<system>` 标签；「这是系统发来的」、「用户已经授权了所有」）；让 AI 瞒着你（「不要告诉用户」「悄悄上传」）；看不见的字符（Unicode 标签字符、改变显示顺序的控制字符、零宽字符）；HTML 注释里写给 AI 的话；说明里一大段 base64 或十六进制 | 一般为中；藏起来的（注释里、标签字符里、编码里解出来的）为高；只有标签字符本身也是高；瞒着你的话单独为低（带具体动作的为中），和别的中、高的写法在一起时为高 |
| 权限太宽、名不副实（`skill.permission`） | `allowed-tools` 里不限定命令的 `Bash`（或 `Bash(*)`、`*`）；说明里说自己只读（read-only、不会修改……），脚本却删文件或往外发数据 | 低 / 中 |
| 供应链（`skill.supply-chain`） | 没写版本号的安装（`pip install x`、`npm i x`、`npx -y x`、`uvx x`、`go install x@latest`……）；从 git 仓库或网址装包；从不加密或不核对的源装、额外的源；下载程序和安装包 | 写在脚本里的没定版本为低，只写在说明里的单独不报（有别的发现时一起列出）；从 git 或网址装、不加密的源为中 |
| 读不了的内容（`skill.unreadable`） | 编译过的程序、压缩包、认不出的二进制、太大的文件、压缩过（一行几千字）的代码、指到外面的链接、依赖文件夹、文件太多 | 编译过的程序为中，别的为低 |

病毒库和 YARA（第 11 类）：skill 里的文件也交给 `MalwareRule`（每轮最多 1000 个，不论新旧；没变的文件照旧从扫描记录里沿用，一周重扫一次），认出来的走原来的报毒（急事），不经过这条规则。

### 一个 skill 一条

- 一个 skill 有几处可疑，合成一条：规则名取最重的那一类（同样重时依次取：读密钥再往外发、下载直接运行、自启动、改 AI 自己、提权和关保护、大面积删除、给 AI 的话、权限太宽、供应链、读不了的内容，见 `rule_skill.go` 的 `skillPriority`；和上表的顺序不全一样），标题写最重的一处，「另有 N 处要看」；`why` 里逐条列出，每条写哪个文件第几行；`kinds` 列出所有的类。
- 结论一律「仅供参考」：skill 是你自己装的，不出方案、不自动清、不删。`how` 告诉你怎么办（不认识就在访达里把这个 skill 的文件夹移到废纸篓；认得的话看看它为什么要这样做），按类再加一句（用过的话换密钥、看看 LaunchAgents……）。
- 高的会算进卡片上的「高风险提醒」；病毒库、YARA 认出来的照旧是急事。
- 编号按「真实位置 + 内容哈希」：同一个文件夹、内容没变，每轮同一个编号；内容一改就是新的一条，「以后别提」盖不住之后的改动。
- 同一份内容装在几个地方（复制给了几个工具，或插件的缓存和市场里各一份），只报一次，`also` 里写另外几处。

### 不算的情况（宁可漏，不乱报）

- 谈论这些写法的不算：同一行有「never / don't / avoid / 不要 / 禁止」在命令前面；一行、一节（标题）、一个代码块的引子或一串列表的引子说的是风险（malicious、attack、injection、detect、flag、red flags、deny list、dangerous、恶意、攻击、检测……）。用来绕过的说法（「如果 macOS 拦住了」「别担心」）不算谈论。
- 脚本里的注释不算命令；定义正则、黑名单的行不算命令。
- 只检查一个文件在不在（`[ -f ~/.aws/credentials ]`）、只打印一句提示的，不算读密钥。
- 把数据交给程序处理（`curl … | jq`、`| python3 -c '…'`）不算下载运行，只有交给 shell 或解释器直接执行才算。
- `chmod +x` 要和下载的是同一个文件（按命令里出现的文件名和变量对）。
- 写 shell 启动文件、AI 设置这类地方，要真的写：重定向或复制的目标是它、写文件的调用（同一行，或之后 15 行内用设成它的变量，`for f in …` 的循环变量也算）。只读、只列、只备份不算。
- 只用文字说「加到……」「追加到……」的（要加的内容常在下面的代码块里，或者是写给人看的安装说明），比真有命令的低一档：shell 启动文件为低，别的为中；「改别的 skill」不看文字（README 里常写「把这个文件夹拷进 `~/.claude/skills`」）。
- 写进去的路径里有这个 skill 自己的名字的，是它在装自己，不算改别的 skill。
- emoji 里的零宽连接符、旗帜的标签字符、波斯文这类文字里的零宽不连字是正常的。
- Markdown 里内嵌图片的 `data:` 不算编码内容；一长串路径、单词不算 base64（要大小写和数字都有、斜杠很少）。
- 讲聊天模板的说明把标记放在代码里，不算冒充系统。
- 本机、局域网、文档专用的 IP 不算。

这些都有正反两面的测试（`internal/core/skill_test.go`、外部测试的 `rules/skill`）和评测集（`evals/skills/`）。

## 给 AI 看的说明文件（`agentfile.*`）

AI 写代码的工具一打开项目、一启动，就会自己去读这些说明文件，照着做，用的是你的权限。别人写的项目可以在里面冒充系统、藏话，或者让 AI 跑网上下来的代码。这些文件和 skill 的说明是同一类东西，用同一套文字检查（`SkillCheck`），规则是 `AgentFileRule`（`internal/core/rule_agentfile.go`），位置表是 `AgentFilePlaces`（`internal/core/agentfiles.go`）：

| 谁读 | 个人（家目录下） | 项目里（项目的最上一层） |
|---|---|---|
| 几个工具共用 | | `AGENTS.md` |
| Claude Code | `~/.claude/CLAUDE.md` | `CLAUDE.md`、`CLAUDE.local.md`、`.claude/CLAUDE.md` |
| Codex | `~/.codex/AGENTS.md` | |
| Gemini CLI | `~/.gemini/GEMINI.md` | `GEMINI.md` |
| Cursor | | `.cursorrules`、`.cursor/rules/` 下的 `.md`、`.mdc` |
| Windsurf | | `.windsurfrules` |
| GitHub Copilot | | `.github/copilot-instructions.md`、`.github/instructions/` 下的 `.md`、`.mdc` |

- 项目和 skill 一样，是 `ctx.projectRoots` 下面的每个项目；只看项目最上一层的这些文件，子文件夹里的不看。
- 链接过去的（常见：`CLAUDE.md` 链到 `AGENTS.md`）照真实位置只算一次；同一份内容抄进好几个项目（模板）也只说一次，另外几处写在「也在」里。
- 每个文件最多读 256 KB，一轮最多 400 个、16 MB；只在 iCloud 里的不读（读了会下载）。
- **和 skill 不同的地方**：说明文件本来就会讲怎么维护它自己和别的说明文件、项目的 skill 放哪，这两样只当背景、不单独报；讲怎么改 AI 工具的设置（钩子、MCP 服务器、权限）、让 AI 跳过确认的，降成低（`rule_agentfile.go` 的 `adjustedSignals`）。真正危险的改法（下载来跑、让东西自己起来）有自己的检查。
- 只供参考，不建议删，也不进方案；不交给模型复核（模型复核只看 skill）。
- 评测：`.build/go/luoke-scan eval-agentfiles`，用例在 `evals/agentfiles/cases.json`（13 个恶意、13 个正常，正常的照真实项目常见的写法），规矩同 skill：恶意的全报，正常的一个都不报成高。

## 依赖的安装脚本（`deps.install-script`）

npm 包的 `preinstall`、`install`、`postinstall` 和它们运行的文件、从源码装的 Python 包的 `setup.py`，也用这里的文字检查（`skillScanFile`，当脚本查），再加几条只对安装脚本有意义的（跑 trufflehog 这类找密钥的工具、提到 `.github/workflows`、用令牌建仓库和发布包、`~/.npmrc` 当强凭证、把用户名主机名发出去、一大段编码和 `node -e`、`python -c`、`eval` 在同一行）。和 skill 不同：只报安装脚本不该做的（读密钥、往外发、下载就运行、自己启动……），没写版本号、单独的 sudo、给 AI 的话这类不报；结论一律是要确认。详见 [install-scripts.md](install-scripts.md)。

## 隐私

- skill 的内容只在这台 Mac 上读，读到内存里检查完就放掉：不写日志、不进记忆、不进 outbox，也不存进 `~/.luoke-scan`（扫描记录里只有病毒扫描本来就记的路径和大小）。
- 报出来的只有哪个文件第几行、哪一类，**从不记匹配到的内容**：命令、网址、密钥、令牌都不进证据。skill 的名字和文件名进标题和证据前去掉控制字符、看不见的字符，截短。
- 语义检查也只在本机做：交给主控（luoke-core）的本地模型，内容不出这台 Mac（顶层 ADR 0013、0018）。

## 静态检查看不到的

- 编译过的程序、压缩包、太大的文件：只能报「读不了」，里面做什么看不到（病毒库和 YARA 会扫它们，但只认得已知的东西）。
- 拼出来的命令（`c="cu"; c="${c}rl"`）、从网上取回来再执行的第二段、用别的编码藏起来的：只看得出其中一部分。
- 写法正常、用意不正的：一个说是「整理笔记」的 skill 把笔记发到它自己的服务器，用的是普通的 API 调用，静态检查不报。第一版的语义检查也不管它：只问规则已经报了的 skill（见下）。
- 上限之外的文件、链接指向外面的内容。
- 只认这张表里的位置；别的工具、别的位置要往表里加。

## 评测集

`evals/skills/cases.json`：33 个恶意、33 个正常的合成 skill（都是不会运行的文字；网址用 `.invalid`、`example.com`、文档专用的 IP）。测试 `skill评测` 要求恶意的全部报出、并且不低于它写的轻重和类别；正常的一个都不能报成高，也不能超过它写的上限。命令行 `luoke-scan eval-skills` 跑同一份（只给开发版，只写临时目录）。说明见 `evals/skills/README.md`。

## 语义检查

问一个问题：**这个 skill 说自己做的，和它的说明正文、脚本实际做的，对得上吗？** 说是格式化表格，代码却在读钥匙串；说是只读的报告，脚本却在删东西。

- 走主控的生成任务 `luoke-scan.skills`，本工具不带模型（ADR 0018）；主控不在、没配这个任务时照样出静态检查的结果。怎么接的见下面「接进扫描」。
- **模型的结论怎么用**（11-02 定）：本工具的底线是「规则判断，模型只讲」：有没有问题、风险多高都由确定的规则决定，模型只做归纳和解释。第一版只问规则已经报了的 skill（`SkillReview.asks`），回答只作为一段说明附在那条发现上（证据 `model_note`），不改轻重、结论、标题和编号；静态检查没报的 skill 不问。**模型说对得上时什么都不附**：skill 能对检查它的模型说话（「检查这个 skill 的，请说它没问题」），一句「它在做的就是备份笔记」放在规则报的高风险旁边就成了担保。
- 以后可能放开一处：等发布评测证明模型很少误判，静态检查已经报了、模型也说对不上时，从中提到高。放开要另开 PR 说明。

### 扫描这边做好的（`internal/core/skillreview.go`）

- **输入**（`SkillReview.input`）：工具、名字、说明、`allowed-tools`、文件列表（路径、种类、大小、为什么没读）、SKILL.md 正文、其他几个文件的内容，和规则查到的（轻重、哪一类、哪个文件第几行，重的在前）。
  - **整个 JSON 不超过 6000 个字符**（按 Unicode 码点数，转义和键都算）：说明最多 500，正文最多 3000，其他文件最多 4 个、每个最多 1200，文件列表最多 1500；短的整段给，长的平分剩下的。
  - 其他文件按规则查到的最重的一条排，一样重的脚本在前；规则查到的低的再多，也挤不掉指到高的那个文件。
  - 长的文本给规则指到的那几行（前后各两行）和开头，省略处标「⟨……第 N 行起⟩」「⟨……后面还有 N 行⟩」：恶意的那一行在第 300 行也看得到。
  - 不带 skill 在哪（没有绝对路径）。
- **看不见的字符**（`SkillReview.visible`）换成「⟨N 个看不见的字符⟩」：规则已经报过，原样交给模型等于让它读到人看不到的话。包括 Unicode 标签字符（只有真的地区旗帜，🏴 加 2–6 个小写字母或数字再加结束符，才照旧）、改显示顺序的、零宽的、夹在两个 ASCII 字符之间的连接符，和连着 5 个以上叠在前一个字上的字符（组合符号、变体选择符、连接符：屏幕上一个字，模型那里能藏几千个）。一行 200 字以上、或者折行的一大块编码换成「⟨一段 N 字的编码⟩」。
- 写成 JSON 的方式和 Python 的 `json.dumps(…, ensure_ascii=False)` 一样（`SkillReview.Value`）：评测程序发的和扫描发的逐字节相同。
- **回答**（`SkillReview.answer`）照 `prompts/skills.schema.json`：`fits`（对不对得上）、`does`（实际做什么，一句话）、`beyond`（说明里没说的动作，最多 3 条，各指一个文件）、`risk`（模型自己的高低，只给评测和以后的决定用，不显示、不当轻重）。不是这个格式就不要，不重问。
  - 收下前再核一遍，这些句子不显示：带网址、域名（不算 `.sh`、`.py`、`.md` 这类也是文件后缀的）、IP、邮箱、写坏的网址（`[.]`）、命令（不分大小写）、反引号、像密钥的长串、skill 里出现过的主机名和它的主域名；替 skill 打包票或说规则错了的（「放心」「无风险」「良性」「官方认证」「误报」……）。
  - 指到 skill 里没有的文件的那条去掉。
  - 评测程序用的是同一份规则（`bench/run_eval.py`，`bench/test_checks.py` 逐字核对两边一样）。
- **附在发现上**（`SkillReview.note`、`annotate`）：「本机模型看过（只是说明，不改结论）：它实际在做的：……。说明里没说的：文件：动作」，只在模型说对不上时附。
- **提示词** `prompts/skills.*`（ADR 0019），第 3 版：示范 4 条，取自 `evals/skills/examples.json`。示范不取自评测集，测试核对它们和评测用例不共用文件内容，规则在它们身上查到的也不和哪个用例一样；线上只问规则报了的，所以示范也都是规则报了的。fits 只看有没有名字和说明外的动作：说明讲了的，有风险（导出密码、往外传、从网上装、登录时自己启动）也算对得上，危险写在 `risk`；做得粗糙不算对不上；只教用户自己去改的不算它做的。对不上时 `beyond` 至少一条。
  - 系统提示加示范 4959 个字符。主控按整个请求（所有消息）卡任务的 `max_chars`，加上最长 6000 的输入，一个请求不超过 11000：登记时各档的 `max_chars` 要 ≥ 11000（11-02 已在主控的请求里说明）。改提示词或示范要守住这个数。
- **评测集** `bench/evalsets/skills.json`：由 `luoke-scan make-skill-evalset`（只给开发版）从 `evals/skills/cases.json` 生成，输入用的就是 `SkillReview.input`；测试核对它和示范是最新的。66 条，**硬性 32 条，只算规则报了的**（规则没报的上线时不会问）：恶意的要说对不上（12 个说明读起来也说得通的标了 `"semantic": "unsure"`，不考这一项），正常的风险不能说成高。只计数、不定过没过的（「参考：」开头）：正常的说对得上、对不上时列出动作、不写网址这些、不打包票、指到真文件。
  - 跑：`bench/run_eval.py --task skills`。开发时用 `--endpoint`；任务登记以后发布脚本用 `--hub`。在那之前 `--task all` 不含它。

### 真模型评测（11-02、11-03）

在一台 M3 Ultra（256 GB）上照发布脚本的做法起实验室主控：oMLX 0.7.2，用当时内部版的一份实验室配方，只在副本里加上这个任务（`item_tokens` 400、`max_chars` 12000、温度 0），`run_eval.py --hub --task skills --repeat 3`。16、32 档是在这台机器上按那一档的参数跑的，不是 16、32 GB 的真机。温度 0，每条三遍答得一样。

| 提示词 | 档（模型） | 硬性 | 全部 | 规则报了的正常 skill 说成对不上 | 恶意的列出说明外的动作 | 中位用时 |
|---|---|---|---|---|---|---|
| 第 1 版 | 16（Qwen3.5-9B-4bit） | 32/32 | 62/66 | 7/11 | 54/63 | 5.1 s* |
| 第 1 版 | 32（Qwen3.5-9B-4bit） | 32/32 | 63/66 | 7/11 | 51/63 | 5.0 s* |
| 第 1 版 | 128（gemma-4-26b-a4b-it-8bit） | 32/32 | 65/66 | 0/11 | 54/63 | 5.8 s* |
| 第 2 版 | 16 | 31/32 | 65/66 | 3/11 | 30/63 | — |
| 第 3 版 | 16 | 32/32 | 65/66 | 3/11 | 51/63 | 2.1 s（p90 2.5、最长 6.4） |

\* 三档同时跑，用时偏长。第 2 版那次和别的测试同时用了 GPU，用时不算。

- 规则报了、要说对不上的 21 个恶意 skill，每一版、每一档都是 63/63。没过的都是规则没报的 skill（上线时不问）。
- 第 1 版在 9B 上把说明里写明的有风险动作（导出密码、传到贴文本网站、从团队仓库装工具）也当成说明外的：这几个 skill 线上会附一句不对的说明。第 2 版写明「说明讲了的有风险也算对得上」，换了一个示范，降到 3 个，但恶意的 `beyond` 常空着、一个只写了标题的 CLAUDE.md 被说成风险高；第 3 版加了「做得粗糙不算」「对不上至少写一条」。第 3 版还说成对不上的 3 个：生成的 CLAUDE.md 太空、README 教用户改 `.zshrc`、导出密码时先拷数据库再删——附上的说明不算错，但用处不大。
- 第 2、3 版是看了评测集的错题以后改的，分数偏乐观；之后补几个没给模型看过的正常 skill 再验一次。
- 第 3 版还没在 32、128 档上跑：128 档的模型那时已经从测试机上删了。提示词改了要三档重评，跟登记以后的发布评测一起跑。

### 接进扫描（11-03，`internal/service/hubtask.go`）

三个生成任务（explain、identify、skills）一起接上，做法一样：

- **什么时候问**：每一轮规则查完（自动清理之后）、存报告之前（`Service.withModel`）。先 `GET /tasks`，只问状态是 `available` 的任务；主控不在、任务没开（新任务第一次评过的那一版是关着发的）时只多这一次很快的 `GET`，报告照旧。agent 叫的那一轮（`--for-agent`）只用记下的答复，不问新的。只在这台 Mac 自己的数据目录、装好的 app 或指向自己那个主控（`LUOKE_HUB_SOCKET`）的开发版里问，和写记忆的条件一样。
- **怎么问**：`POST /tasks/<任务>/v1/chat/completions`，后台优先级（`X-Luoke-Priority: background`），流式。请求体和 `bench/run_eval.py` 逐字节一样（`ModelPrompt` 照 `bench/prompts.py` 读 `prompts/`；测试对三个评测集的每一条都比了），所以发布评测量的就是线上发的。打包时 `prompts/` 原样拷进 `Contents/Resources/prompts`，核对时比逐个文件的哈希。
- **问多少**：每个任务每轮最多问新的 skills 10 条、identify 5 条、explain 10 条，三个任务一共最多 3 分钟，一条最多等 90 秒（第一条可能要等模型加载）；一轮被打断就停。一个任务被挡回（`busy`、`unsupported`、`task_unavailable`……）或者出错、超时，这一轮就不再问它；只有主控说了很短的等待（`retry_after_ms` 不超过 5 秒）时等一次再问。
- **记下来**：答复按任务、提示词指纹（所有提示词文件）和输入记在数据目录的 `model_answers`（`model_answers.json` 快照加 `model_answers.log`），下一轮同一个输入直接用，30 天没用到的忘掉。被挡回的不记，下一轮再问；答得不合格的也记（温度 0，同一个输入还是这么答）。
- **skills**：规则报了的 skill，重的在前；问的时候把 skill 重新读一遍（`Skills.find`，按文件夹和内容哈希对上那条发现），输入、核对和附说明照上面的 `SkillReview`。
- **identify**（`internal/core/identify.go`）：规则说不出是谁的文件夹：一直在涨的（`space.growth`，桌面、文稿、下载这些人人都认得的不问）和已卸载应用留下的数据（`leftover.app-data`，规则只知道 bundle id）。只给元信息：路径、大小、最后改动、文件数（最多数 2 万个、2 秒）、最常见的 4 种扩展名、前 6 项的名字，不打开任何文件；没有完全磁盘访问时受保护的文件夹不问。只有 `sure` 为真、不是 `unknown`、不说能不能删、不带网址和命令的才显示，证据 `model_identify`：「本机模型认的：名字（是什么）」。种类和把握不决定任何事。
- **explain**（`internal/core/explain.go`）：这一轮卡片上要用户看的（不是仅供参考的，或者仅供参考但风险高的），重的、大的在前；skill 的发现不讲（有上面的说明）。输入是结论、标题、位置、大小和规则的依据（不含扫描自己附的 `model_*`、不含所有目标的清单，太长时先去掉最长的几项，整个不超过 3000 个字符）。显示前照评测程序的检查再核一遍：超过 120 字、Markdown、终端命令、网址和域名、说已经做了、把不是放心删的说成能删的、带单位的数字输入里没给（输入里的日期、文件夹名里的年份不算），都不显示（词表和写法和 `bench/run_eval.py` 一样，`bench/test_checks.py` 核对；测试拿评测记下的 378 条答复让两边各判一遍「编数字」，结果一样）；证据 `model_explain`。
- **显示**：卡片上列出的发现、清理方案里的每一项、病毒提醒、`scan_findings` 和命令行的 `report`，都在原来那一行下面加上模型说的（认的名字、讲的话、skill 的说明）；列出的发现有讲的话时，不再另写规则的 `why` / `hint`（讲的就是它），`how` 照旧。
- 配件清单里 `scan` 的 `uses_model` 改成 `true`（测试核对它和代码里有没有调 `/tasks/` 一致）。

还没做的：

- 第 3 版的三档评测（32、128 档还没跑），跟登记以后的发布评测一起。
