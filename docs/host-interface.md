# 螺壳本体怎么接扫描

给写螺壳本体（Swift）的人：本体怎么起扫描、怎么把连接交给 agent、怎么替扫描弹密码框。扫描这一侧的代码在
`internal/service/host.go`（提权通道）、`internal/service/elevate.go`（root 跑的那条命令）、`internal/service/mcp.go`（MCP）、
`cmd/luoke-scan-admin/`（root 那一步）。定下来的事（11-05）：每个请求一条连接；本体起 `luoke-scan mcp`；
要密码的那一步由本体弹框，框上是螺壳；agent 那边由本体给连接，不自己起扫描。

## 1. 包在哪、里面有什么

扫描打进螺壳.app，跟螺壳一起升级、一起签名、公证，但不生成任何 .app（顶层 ADR 0022 的 11-05 修订）。
和螺壳搜索一样放裸程序：程序在 `Contents/Helpers`，库在 `Contents/Frameworks`，数据在 `Contents/Resources` 下
（Helpers 里放非程序文件，外层签名会失败）。下面的 `<螺壳>` 指螺壳.app。

| 位置（在 `<螺壳>/Contents/` 下） | 是什么 | 签名标识 |
|---|---|---|
| `Helpers/luoke-scan` | 主程序 | `ai.luoke.scan` |
| `Helpers/luoke-scan-admin` | 要密码的那一步，以 root 跑 | `ai.luoke.scan.admin` |
| `Helpers/clamscan`、`freshclam`、`sigtool`、`yara` | 病毒扫描器，只由 `luoke-scan` 当单独的程序起 | `ai.luoke.scan.clamscan` 等 |
| `Frameworks/`（`libclamav.12.dylib` 等） | 上面四个要的动态库（ClamAV、YARA、OpenSSL…），工具的 rpath 是 `@executable_path/../Frameworks` | 各自签 |
| `Resources/scan/luoke-accessory.json` | 配件清单 | 随螺壳 |
| `Resources/scan/bundled-tools.json`、`AppIcon.icns` | 带进来的程序和库的清单、「应用」窗口里显示的图标 | 随螺壳 |
| `Resources/licenses/luoke-scan/` | 第三方许可证和说明（`THIRD-PARTY.md`） | 随螺壳 |

提示词、`freshclam.conf`、ClamAV 根证书和 Info.plist（`__TEXT,__info_plist`：`CFBundleIdentifier` 是 `ai.luoke.scan`，
`CFBundleShortVersionString` 是版本号）编在 `luoke-scan` 里面。正式版的 `luoke-scan` 每次用 Helpers 里的工具以前核签名
（标识 `ai.luoke.scan.<名字>`，加上编进去的发行团队），不对就当没有。

**打包**：luoke-core 的 `app/build_app.sh` 给了 `LUOKE_SCAN_SRC` 才带扫描。用那个提交的 `scripts/package_app.py --out <临时目录>`
编出 `luoke-scan/`（里面就是上表的 `Helpers/`、`Frameworks/`、`Resources/`，临时签名、标识已定），`Resources`、`Frameworks`
在外层 `--deep` 签名之前拷进去，`Helpers` 在那之后拷进去，再不带 `--deep` 签一次外层。正式签名用 `tools/release_sign.sh`：
Helpers 里的程序保留标识，统一加 hardened runtime。之后谁也别用 `--deep` 重签：标识会被盖掉，`luoke-scan` 认不出工具，
root 那一步也认不出 `luoke-scan-admin`。签好以后跑同一版的 `scripts/package_app.py --verify-app <螺壳.app>` 核对扫描的那些。

**起之前核签名**：螺壳可能装在用户的程序能改的地方（`~/Applications`），所以本体起 `luoke-scan` 以前照旧核对（本体是临时签名的
开发版时不核）：

```
=anchor apple generic and identifier "ai.luoke.scan" and certificate leaf[subject.OU] = "<螺壳自己的团队>" and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13]
```

核对和起之间不能留空档（中间换掉文件，起来的就是别的程序，带着螺壳的完全磁盘访问）：

- 停着起、核运行中的进程：`POSIX_SPAWN_START_SUSPENDED` 起，用 Security 框架按 pid（`kSecGuestAttributePid`）取它的 SecCode，
  用同一条要求 `SecCodeCheckValidity`，过了 `SIGCONT`，不过 `SIGKILL`。注意同一个用户的别的进程也能给它发 `SIGCONT`：
  放行前要确认它还停着、还没跑过。
- 让内核在起的时候核：macOS 14.4 起 `Process.launchRequirementData`（LightweightCodeRequirements 的 `LaunchCodeRequirement`）。
  要先确认它能不能交出标准输入输出以外的描述符（描述符 3）。

版本：签名里的 `CFBundleShortVersionString` 要等于螺壳打包时带的那一版，防有人把 Helpers 里的程序换成旧版的签名程序。
那一版由 `build_app.sh` 写进螺壳自己的 Info.plist（`LuokeScanVersion`），螺壳的签名盖住它。

清单里给 agent 的：`capabilities.transport` 是 `"stdio"`（不再有 `socket`）；空闲任务的 `exec` 是 `"luoke-scan"`（Helpers 里的程序名）。
权限只在 `capabilities.permissions` 里声明一次；空闲任务用到哪项写 `"uses": ["fda"]`。

## 2. 起 `luoke-scan mcp`

一个 MCP 请求一个进程：

```
<螺壳>/Contents/Helpers/luoke-scan mcp --this-mac
```

- **标准输入、标准输出**：都接在交给 agent 的那条连接上（一对 `socketpair` 的一端；另一端经 `SCM_RIGHTS` 给 agent）。
  agent 写**一条** JSON-RPC 消息（一行，结尾 `\n`），读一行答复，关掉连接；扫描答完那一条以后读到结尾就退出。
  通知（没有 `id` 的消息）不答：agent 发了通知就直接关。一条消息最多 1 MB，超了扫描不答、退出码 3。
- **标准错误**：接到本体的日志。扫描只在出事时写一两行中文（比如状态文件读不了、挪开了）。
- **描述符 3**：提权通道（见下一节），另一对 `socketpair` 的一端；环境变量 `LUOKE_HOST_FD=3`。别的描述符不要漏给它。
- **工作目录**：`/`。
- **环境**（只给这些）：
  - `HOME`：用户的家目录；
  - `TMPDIR`：这个用户的临时目录（`confstr(_CS_DARWIN_USER_TEMP_DIR)`，即 `/var/folders/…/T/`）：扫描要查它；
  - `PATH=/usr/bin:/bin:/usr/sbin:/sbin`、`LANG=en_US.UTF-8`；
  - `LUOKE_HOST_FD=3`；
  - `LUOKE_PERMISSIONS_OFF`：这个应用还不能用的权限，清单里的编号，逗号分隔（比如 `fda`）：清单里声明的、归螺壳的系统权限
    （`kind` 是 `system`、`owner` 是 `luoke`）当中，用户还没在螺壳里确认给这个应用用的，从来没确认过的和确认过又关掉的都算；
    都确认过就不给。
    里面有 `fda` 时，不管 macOS 给没给，扫描都当没有完全磁盘访问：受保护的文件夹和 TCC 数据库不碰，一轮照常说哪些没查；
    `permissions` 资源答 `denied`；照样发「需要你允许」（`needs-access`）那一件：这一项还要用，用户点了卡片，本体才再问。本体起的每个扫描进程都要给，
    包括空闲任务（§7）；`scan_now` 起的那一轮从 `luoke-scan mcp` 继承。用户改了开关，下一个进程起就按新的算；正在跑的一轮不变。
  - 开发时另可给 `LUOKE_HUB_SOCKET`（指向开发用的主控，没给就用正式主控的 socket）、`LUOKE_HOME`、`LUOKE_MEM_TEST`（测试用的记忆）。
    正式版不给这几个。
- **参数**：正式版只认 `--this-mac`（打包时编进去的标记，开发用的 `--home`、`--data`、`--fixture`、`--clock` 一律拒绝）。
  开发时可以起开发版的扫描对假目录：`luoke-scan mcp --fixture <假目录> [--clock <ISO 8601>] [--no-full-disk-access]`。
- **退出码**：0 答完了（或只是通知）；3 没读到消息，或消息超过 1 MB；64 参数不对；别的是出错了（标准错误里有原因）。
- **超时**：本体 300 秒还没答完就结束它。扫描自己在这之前答：执行方案（`scan_apply`）从开始算 285 秒内答完，核对和
  密码框共用这段时间；核对花得太久、剩下不到 60 秒时不弹密码框，什么都不动，答「再点一次」；弹框时等的时间也不超过剩下的（最多 280 秒）。
- **并发**：同时可以有几个 `luoke-scan mcp` 在跑；数据目录（`~/.luoke-scan`）上的锁扫描自己管。
- `scan_now` 会另起一个脱离的 `luoke-scan scan --for-agent --this-mac`（它自己的进程组），这个请求的进程先答完退出，那一轮接着跑。
  答之前最多等 3 秒，等那一轮拿到锁：agent 点完马上读的 `summary` 已经是「正在查」。
- 两轮之间看一眼新下载的（`luoke-scan scan --this-mac --quick`，只扫病毒；有没有新下载的、现在合不合适由它自己定，没有就马上退出）
  还没有入口：主控的空闲任务只有 `update` 和 `scan`，本体也只放行这两条（§7）。要等主控加一个专门的空闲任务（隔几分钟起一次）、
  本体放行它。读 outbox、读页这些只读的请求不起任何东西。
- 完全磁盘访问：授给螺壳，由本体起的扫描跟着用；扫描起的程序也一样。扫描开 `TCC.db` 探有没有这个权限（不会弹框）；没有时，
  桌面、文稿、下载这些会让 macOS 问用户的地方一律不看，在报告里写明。

## 2a. 启动时认本体

装好的扫描（打包时编进标记的那一份）不管谁起都带螺壳的完全磁盘访问：系统按程序在不在螺壳.app 里认身份。所以它启动时先看是不是螺壳起的，
不是就退出码 77，标准错误一句「不是螺壳起的（原因）」，什么都不做。不用看的只有 `version`、`report`、`findings`、`status`（只读上一轮写好的报告）。
开发版不看。

看的是（`internal/service/fromapp_darwin.go`），按这个顺序：
1. 描述符 3 是 Unix 的流 socket；
2. 对面那一头（`LOCAL_PEERPID`：最后一个读写它的进程）是扫描的父进程，而且父进程**这一刻**跑的是同一个 .app 的主程序：按内核给的
   audit token（`LOCAL_PEERTOKEN`）核它正在跑的程序的签名（Security.framework），要苹果签发、是螺壳发布用的团队（编进去的
   `core.ReleaseTeam`）、标识是 .app 的 `CFBundleIdentifier`；程序文件（`proc_pidpath`）是 `Contents/MacOS/<Info.plist 的 CFBundleExecutable>`。
   没编团队的打包（本机的开发版、试用版，整个 .app 临时签名）不核签名，其余照旧；团队是编进去的，运行时（环境变量、换个签名）改不了；
3. 这以后才写一行 `{"id":"<16 字节随机数>","method":"hello"}`，5 秒内要读到一行答复，`id` 要一样（答什么都行，本体对不认识的请求
   答 `failed` 就够了，`id` 原样带回）；
4. 答完以后对面还是父进程，audit token 里的 pid version（exec 一次就变）和第 2 步时一样。

顺序是有讲究的：对面的 audit token 是「取的那一刻」这个 pid 上跑的程序的，不是写那一行时的（macOS 27 上量过）。要是答完才核，
父进程可以先自己答、再 exec 成本体（pid 不变）就过了。现在父进程在有东西可答以前就得已经是本体；答复要带新随机数，不能事先写好；
父进程留下别的进程来答，对面记的就是那个进程。

本体这边要做的：§2 的描述符 3 已经满足；§7 的空闲任务也给一个（见那里）。`scan_now` 起的那一轮由 `luoke-scan mcp` 起，
它自己先过了这一关，再给那一轮一对 socket 答话，那一轮认「同一个 luoke-scan」做父进程也算（只有 `scan --for-agent`；签名的标识认扫描自己的）。
看完以后描述符 3 只在 `LUOKE_HOST_FD=3` 时留着（并且不漏给扫描起的程序），否则关掉。

## 3. 提权通道（`LUOKE_HOST_FD`）

一行一条 JSON，两个方向都是。扫描一次只发一个请求，等答复（弹密码框最多 280 秒，§3a 的最多 15 秒）。

请求：

```json
{"id": 1, "method": "elevate", "params": {
  "args": ["--plan", "p-0123456789ab", "--user", "501", "--keys", "a0,a1", "--apps", "com.example.app,org.example.tool", "--homebrew"],
  "prompt": "螺壳扫描要把系统目录里 2 个应用留下的东西（1.2 GB）移到废纸篓。"}}
```

本体收到后**逐项核对 `args`**，有一项不对就答 `failed`，不弹框：

- 顺序固定：`--plan`、`--user`、`--keys`、`--apps`，最后可以有一个 `--homebrew`；不多不少。
- `--plan`：`^p-[0-9a-f]{12}$`。
- `--user`：十进制，必须等于本体自己的 `getuid()`。
- `--keys`：逗号分开，每一项 `^a[0-9]{1,3}$`，至少一项。
- `--apps`：逗号分开，可以是空串（只有带 `--homebrew` 时）；每一项 `^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+){2,}$`。
- `prompt`：只用来显示在框上（扫描拼的一句话），不进命令；太长就截到 500 个字。

答复，三种之一：

```json
{"id": 1, "result": {"status": "done", "output": "<luoke-scan-admin 的标准输出，原样>"}}
{"id": 1, "result": {"status": "cancelled"}}
{"id": 1, "result": {"status": "failed", "why": "删除程序的签名不对，没有动任何东西"}}
```

- `done`：root 那一步跑完了（不管它移成了几项）。`output` 是它的标准输出：一行一条 JSON，每一项一行
  （`key`、`path`、移成了的有 `trashed`、`device`、`inode`、`bytes`，没移的有 `error`，已经不在的 `gone: true`）。
  扫描自己读它、记清理记录、回卡片。
- `cancelled`：用户关了密码框，什么都没跑。
- `failed`：`why` 是给用户看的一句中文。带 `"uncertain": true` 的是本体等到时限不等了：框关了，但 root 那一步可能已经做了一部分、
  还在跑。扫描这时把已经挪走的记进清理记录，留着待核对的那份，下一轮（或放回时）再核一遍。其余的照 shell 的退出码：72 →「删除程序的签名不对，没有动任何东西」；
  73 →「删除那一步出错了」；70、71 →「删除程序没能准备好」；参数不对 →「参数不对，没有动任何东西」；开发版（没有团队签名）→
  「开发版不能删系统目录里的东西」。

## 3a. 叫到前面：`reveal`、`open_settings`

macOS 只让当前在前面的应用把别的应用叫到前面。用户在螺壳里点了「在访达里显示」「打开设置」时在前面的是螺壳，扫描是后台程序：
它自己跑 `open -R`、`open <地址>` 能开出窗口，但访达、系统设置不一定到前面，会被螺壳的窗口挡住。所以由本体做：

```json
{"id": 2, "method": "reveal", "params": {"path": "/Users/me/Downloads/x.dmg"}}
{"id": 3, "method": "open_settings", "params": {"pane": "Privacy_AllFiles"}}
```

- `reveal`：本体核对 `path` 是存在的绝对路径（不带换行、NUL），在主线程上 `NSWorkspace.shared.activateFileViewerSelecting`。
- `open_settings`：`pane` 只认这几个，地址由本体拼，不收扫描给的地址：`Privacy_AllFiles`、`Privacy_Accessibility`、
  `Privacy_ScreenCapture`、`Privacy_ListenEvent`、`Privacy_FilesAndFolders`、`Privacy_Camera`、`Privacy_Microphone`、
  `Privacy_Automation`、`FDE`（`x-apple.systempreferences:com.apple.preference.security?<pane>`），`LoginItems`
  （`x-apple.systempreferences:com.apple.LoginItems-Settings.extension`），`Battery`
  （`x-apple.systempreferences:com.apple.Battery-Settings.extension`），`ActivityMonitor`（不是设置页，是打开应用
  `/System/Applications/Utilities/Activity Monitor.app`；含空格，本体用文件地址 `URL(fileURLWithPath:)` 开）。
  后两样是运行状况的发现用的；本体还没加这两页时答 `failed`（不认识的 `pane`），扫描就自己 `open`，窗口可能在螺壳后面。
- 两样都只紧跟在用户的点按后面做：螺壳在最前、10 秒内点过或按过键（本体的 `UserAction.recent()`），不是就答 `failed`。
- 答 `{"status": "done"}` 或 `{"status": "failed", "why": "…"}`。`failed`、没有这条通道、本体不认识这个请求（旧版本体答
  「不认识的请求」）时，扫描自己 `open -R <路径>`、`open <地址>`，和以前一样。
- 不限扫描：本体起的工具都能请这两样（`elevate` 仍只给扫描）。

## 4. root 跑的那条命令

信任在 root 那一侧建立：本体用自己包里的 `luoke-scan-admin`（`<螺壳>/Contents/Helpers/luoke-scan-admin`，
路径由本体自己定，不从扫描那里来），root 先把它拷进只有 root 能写的临时目录，在那里核对签名，再用空环境跑拷贝。
照扫描的 `AdminCommand`（`internal/service/elevate.go`）拼成一条 `sh -c` 的命令，每个参数用单引号包好（`'` 写成 `'\''`）：

```sh
umask 077
d=$(/usr/bin/mktemp -d /private/var/tmp/luoke-scan-admin.XXXXXXXX) || exit 70
trap '/bin/rm -rf "$d"' EXIT
[ ! -L '<helper>' ] && [ -f '<helper>' ] && [ $(/usr/bin/stat -f %z '<helper>') -lt 104857600 ] || exit 71
( ulimit -f 204800; /bin/cp -X -P '<helper>' "$d/luoke-scan-admin" ) || exit 71
[ ! -L "$d/luoke-scan-admin" ] && [ -f "$d/luoke-scan-admin" ] && [ $(/usr/bin/stat -f %z "$d/luoke-scan-admin") -lt 104857600 ] || exit 71
/usr/bin/codesign --verify --strict -R '<requirement>' "$d/luoke-scan-admin" || exit 72
/usr/bin/env -i PATH=/usr/bin:/bin "$d/luoke-scan-admin" '<arg1>' '<arg2>' … || exit 73
```

（实际是用 `; ` 连成一行。）`<requirement>`：

```
=anchor apple generic and identifier "ai.luoke.scan.admin" and certificate leaf[subject.OU] = "<团队标识>" and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13]
```

**团队标识从本体自己的签名里取**（`SecCodeCopySelf` → `SecCodeCopySigningInformation` 的 `kSecCodeInfoTeamIdentifier`），
不写在源码里。本体是临时签名（开发版，没有团队）时不提权，直接答 `failed`。

## 5. 弹框（Swift 版原来的写法）

Swift 版（`backup/swift` 分支，`Sources/ScanService/Admin.swift` 的 `Elevate`）在发起请求的那个短命进程里这样做：

```swift
let script = "do shell script \(appleString(command)) with prompt \(appleString(prompt)) with administrator privileges without altering line endings"
var error: NSDictionary?
let out = NSAppleScript(source: script)!.executeAndReturnError(&error)
if let error {
    let code = error[NSAppleScript.errorNumber] as? Int
    if code == -128 { /* 用户取消 → cancelled */ }
    if code == 72 { /* 签名不对 → failed */ }
    /* 其余 → failed：error[NSAppleScript.errorMessage] */
}
/* 成功 → done：out.stringValue */

static func appleString(_ s: String) -> String {
    "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
}
```

**一定要先清环境**：授权服务会把发起进程的环境变量和工作目录交给 root 的 shell，shell 在跑第一条命令以前就会读其中一些
（`SHELLOPTS`、`PS4`、导出的函数……），用户的任何程序都能借 `launchctl setenv` 之类把它们塞进螺壳的环境，
在签名核对之前以 root 跑起来。Swift 版在调用前把整个进程的 `environ` 换成只有 `PATH=/usr/bin:/bin:/usr/sbin:/sbin`、
再 `chdir("/")`，并核对确实只剩这一项（`scrubEnvironment`）。

本体是长驻进程，不能把自己的环境换掉。建议：本体起一个只做这一件事的子进程，用的是螺壳包里的程序（比如本体可执行文件带一个
专用参数），用 `posix_spawn` 给它只有 `PATH` 的环境、工作目录 `/`、只有标准输入输出错误三个描述符；它在里面跑上面的
NSAppleScript，把结果写回标准输出。框上的应用名是这个程序的，所以要是螺壳包里的。

## 6. 本体要测的

- 参数核对：上面每一条不对的写法都答 `failed`、不弹框。
- 团队标识取不到（临时签名）时不弹框。
- 环境：子进程里除了 `PATH` 什么都没有（可以让它先把环境写出来再比）。
- 取消、签名不对（拿一个别的签名的 `luoke-scan-admin` 试）、成功三种都走一遍；成功的那次只对假的方案和假的系统目录跑，
  不对真机的 `/Library`。
- §3a：不是绝对路径、路径不在、不认识的 `pane`、给的是地址都答 `failed`，不开访达和系统设置；螺壳不在最前时答 `failed`。

## 7. 空闲任务（主控经本体起）

主控不直接起扫描，而是起螺壳本体的 `--run-tool luoke-scan <清单里空闲任务的 command>`（比如 `update --this-mac`、
`scan --this-mac --autoclean`），由本体照 §1 核对签名、放行。接口是本体那边定的，扫描这一侧要知道的是：

- 标准输入、输出是 `/dev/null`，标准错误进主控的任务日志；工作目录 `/`；环境同 §2（`HOME`、`TMPDIR`、`PATH`、`LANG`，有还没确认的权限时还有 `LUOKE_PERMISSIONS_OFF`）。
  没有 `LUOKE_HOST_FD`：空闲任务不提权。描述符 3 是本体（`--run-tool` 那个进程）给的一对 socket 的一端，只用来认是螺壳起的（§2a）；
  在上面请什么本体都答 `failed`。
- **停**：主控要它停时（比如用户回来了），本体把 SIGTERM 转给扫描。扫描在当前这一步之后停；正在跑的工具（clamscan 之类）先收到 TERM，
  两秒后 KILL。到了收尾的时限还没退，主控对整个进程组 SIGKILL。SIGINT、SIGHUP 扫描不接，收到就直接退出。
- **进程组**：扫描起的工具都留在扫描自己的进程组里（0.2.2 起；以前每个工具单独一个组，按组硬杀杀不到它们），按组杀会一起带走。
  只有 `scan_now` 起的那一轮故意脱离（它自己一个组，§2）。
- **第一轮先下病毒库**：`scan --this-mac` 起来发现还没有病毒库时，先照 `update` 下载一次（每天最多一次，最多 10 分钟），再查；
  主控在用户开启时马上起 `scan`，`update` 要等下一个安静时刻。下不成就照常查，病毒那一项写明没查的原因。
- **只放行写死的**：本体只认两条完整的命令，一字不差：`update --this-mac` 和 `scan --this-mac --autoclean`。清单的空闲任务
  要和这两条一致；改了的话得同时改本体（`HostedTool.known`），不然 `--run-tool` 退 120，扫描根本起不来。
- **退出码**：扫描的照传；被信号结束的是 128 加信号值。120–123 是本体自己的：120 参数不对、121 没装好或用户没开启、122 起不来、
  123 签名不对。扫描自己不用这几个（现在只用 0–4、64 和 77：不是螺壳起的，§2a），日志里才分得清是谁出的错。
- 开发版和实验室的环境多一个 `LUOKE_HUB_SOCKET`，同 §2。
