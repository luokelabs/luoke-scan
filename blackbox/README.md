# 从外面测（blackbox）

只通过命令行测 `luoke-scan`：造一份假目录，一步一步跑命令，看输出和假目录里的文件怎么变，和 `golden/` 里存的比。
不看数据目录、不看程序里的类型，所以换一种写法的 `luoke-scan` 也能拿同一套来对：golden 是 Swift 版录的，Go 版（11-05 换过来）照它全部对上。

```sh
go build -o .build/go/luoke-scan ./cmd/luoke-scan
python3 blackbox/run.py                      # 跑全部场景，和 golden 比；不一样就列出差别，退出码 1
python3 blackbox/run.py --only rules/cache   # 只跑名字以它开头的
python3 blackbox/run.py --record --only …    # 重录（先确认差别是该有的）
python3 blackbox/run.py --list               # 列出场景
LUOKE_SCAN_BIN=/path/to/luoke-scan python3 blackbox/run.py   # 换一个被测的程序（也可以 --bin）
```

只用 Python 标准库。每个场景在新建的临时目录里跑，跑完删掉（`--keep` 留下）；被测的程序看到的 `HOME` 是那里的一个空目录。
不碰家目录、不连主控、不联网、不跑 `--this-mac`、不要密码。

## 目录

- `run.py`：入口。`harness.py`：跑一个场景、换占位。`fx.py`：造假目录。`tools/`：假的 clamscan、freshclam、sigtool、yara。
- `cases/*.py`：场景，用 `@case("名字", "一句话")` 登记。名字就是 `golden/` 下的路径。
- `golden/`：每个场景一份 JSON：每一步跑了什么、退出码、输出（JSON 输出解开存）。

## 假目录模式的约定

被测的程序要支持 `--fixture <根>`（`scan`、`mcp`、`cleaned`、`restore`、`system`）和 `--clock <ISO 8601>`。假目录里：

| 路径 | 是什么 |
|---|---|
| `home/` | 家目录；`home/Projects` 是唯一的项目目录，`home/Applications` 是唯一的应用目录 |
| `tmp/` | 本用户的临时目录 |
| `tools/` | 扫描器：`clamscan`、`freshclam`、`sigtool`、`yara`、`XProtect.yara` |
| `data/` | 扫描自己的数据，被测的程序自己建；场景不碰 |
| `SystemLibrary/`、`receipts/` | 当 `/Library`、`/var/db/receipts` |
| `Shared/`、`usr-local/`、`opt-homebrew/`、`etc/`、`usr-sbin/` | 当 `/Users/Shared`、`/usr/local`、`/opt/homebrew`、`/etc`、`/usr/sbin` |
| `Trash/` | 废纸篓：移到废纸篓的都进这里（名字前加 8 位十六进制和 `-`） |
| `commands.log` | 要跑的系统命令（不真跑）：一行一个 `{"tool", "args"}` |
| `fakes.json` | 本机状态的假答案，见下 |

TCC 只读 `home/Library/Application Support/com.apple.TCC/TCC.db`。不调 launchctl、不看真机的进程、Spotlight、磁盘映像、
登录项、crontab。门槛比真机低，免得要造上 GB 的文件：每天涨 1 MB 就算在涨，重复文件、很久没用的大文件、系统恢复镜像 1 MB 起。

`fakes.json` 每个键都写（`fx.standard_fakes` 是全部的键）：

| 键 | 答的是 |
|---|---|
| `processes` | 进程表：`pid`、`ppid`、`uid`、`path`、`started`；可以另带 `arguments`（argv，程序在第一个；不写是读不到）和 `listening`（监听的 TCP：`port`、`address`） |
| `launchdPIDs` | launchd 起的进程号；`null`：launchctl 没答 |
| `commands`、`otherCommands` | 系统命令的答复（`defaults`、`launchctl`、`fdesetup`、`socketfilterfw`、`csrutil`、`spctl`、`security`、锁屏的 `/bin/sh`）：第一条 `tool` 相同、`args` 都在参数里的；都不是就用 `otherCommands`。登录项也从这里来：`launchctl print gui/<uid>` 和 `launchctl print gui/<uid>/<标签>` 的原样输出 |
| `bootTime`、`pendingUpdates`、`xprotectUpdated` | 开机时间、等着装的系统更新、XProtect 上次更新 |
| `signatures`、`otherSignature` | 常驻项检查看到的签名：第一条 `pathContains` 在路径里的；程序不在就是 `missing`。写法 `apple`、`developer:<团队>`、`adhoc`、`unsigned`、`invalid`、`script`、`unknown` |
| `codesign` | 键盘监听的程序、浏览器扩展能启动的本机程序、启动钩子：`{路径: 签名}`，写法同上；没列的真跑 `codesign` |
| `appTrust` | 新应用：`{应用路径: 担保}`，`apple`、`appStore`、`notarized`、`developer:<团队>`、`adhoc`、`unsigned`、`invalid`；没列的真查 |
| `eventTaps` | 键盘事件监听：`program`、`listenOnly`、`allApps`、`pid`；`null`：不知道 |
| `snapshots` | Time Machine 本地快照的时间；`null`：tmutil 没答 |
| `appleSilicon` | 是不是 Apple 芯片 |
| `running`、`commandLines`、`attachedImages` | 正在跑的程序的路径、它们的命令行、挂着的磁盘映像 |
| `crontab` | 本用户的 crontab；`null`：读不了 |
| `installedCommands` | 装着的命令（缓存自己的清理命令要它在） |
| `volume` | 家目录所在的盘：`free`、`total`、`swap`（字节）；`null`：不知道 |
| `onBattery`、`lowPower`、`memoryPressure` | 两轮之间看一眼新下载的（`scan --quick`）要等的：在用电池、低电量模式、内存压力（1 正常、2 警告、4 严重） |
| `staleFiles`、`downloaded`、`appsAdded` | Spotlight 的答复：很久没用的文件（`path`、`used`、`changed`）、最近下载的文件、应用来到文件夹的时间；前两个 `null`：Spotlight 没答 |

没在 `codesign`、`appTrust` 里列的签名检查（还有安装包的），对假目录里的文件真的跑 `codesign`。常驻项看
`home/Library/LaunchAgents`、`SystemLibrary/LaunchAgents`（所有用户的）、`SystemLibrary/LaunchDaemons`（系统的）；
登录项按 bundle id 找应用只在 `home/Applications` 里找。

## 写场景

```python
from fx import MiB, T0, days
from harness import Run, case

@case("rules/cache/pip", "pip 的缓存够大：放心删")
def pip(r: Run) -> None:
    r.fx.file("~/Library/Caches/pip/http/blob", size=60 * MiB, at=days(3))
    r.update()          # 假的病毒库
    r.scan(T0)          # 查一轮，记下报告
```

- `r.fx`：`file`、`dir`、`plist`、`json`、`link`、`app`、`repo`、`commit`、`tcc`、`quarantine`、`adhoc_sign`、`touch`、`age`、`remove`；
  路径写 `~/…`（家目录）、`$TMPDIR/…`、或相对于根。时间默认 `T0`（2026-10-20 12:00 UTC）。
- 本机状态：`r.fx.fake("键", 值)`、`r.fx.command(tool, output, args=…, status=…)`。场景默认从一台没毛病的 Mac 起
  （`quiet_fakes`：只开着一个应用，FileVault、Gatekeeper 开着，没有等着装的更新），结果里只有要看的东西。
- 跑命令：`r.scan(时钟, *参数)`、`r.update()`、`r.cli(*参数, json_out=…, stdin=…)`；`r.note("改了什么")` 记一步不是跑命令的。
- agent 的请求：`r.mcp(方法, 参数, clock=…, user_action=…)` 起一次 `luoke-scan mcp --fixture … --clock …`（标准输入一条
  JSON-RPC）；`r.mcp_raw(文字, clock=…)` 原样发。`agent.Agent(r, 时钟)` 照 luoke-agent 的做法：`connect()`、`look()`（outbox、
  概览、权限、基础页）、`read(uri)`、`item(种类, 标题)`、`click(事件, 按钮上的字, item=… 或 page=…, choose=…)`（换好按钮的
  上下文、带上 `ai.luoke/user-action`）、`call(工具, 参数)`、`wait_round(时钟)`（等 `scan_now` 另起的那一轮查完）。

调模型：`r.start_hub({任务: 状态}, {任务: 答复})` 起一个假主控（`hub.py`：`/tmp` 下一个 Unix socket，`GET /tasks`、
`POST /tasks/<任务>/v1/chat/completions` 的流式答复；答复可以是文字、拒绝、`luoke.error`、坏的块、断掉的流），之后的命令带着
`LUOKE_HUB_SOCKET`。假目录模式里给了它就问模型（开发版才认），照旧不写记忆。每一步主控收到的请求（路径、请求头、请求体）
原样记进 `hub`：发给模型的请求要逐字节一样。

每跑一次命令，前后各量一遍假目录（`home`、`tmp`、`Trash`、假的系统目录；不看 `data`、`tools`、`.git` 里面）：多了、少了、
变了的文件（类型、大小、权限、文件的修改时间、链接指向、扩展属性的名字）记进这一步的 `tree`，只读的命令一旦改了文件，
golden 里马上看得出来。假目录模式下扫描不真跑系统命令（`open`、`launchctl`），一行一条记进 `<根>/commands.log`，
这一步新记的放进 `commands`。

清理记录里的 inode、设备号换成 `$INODE`、`$DEVICE`；由路径和随机数算出的 12 位编号按出现的先后换成 `000000000001`……；
移进废纸篓时加的随机前缀写成 `XXXXXXXX-`；`gui/<uid>` 写成 `gui/$UID`；扫描自己的版本号写成 `$VERSION`；假主控的
socket 写成 `$HUB`；被截短的长路径里落在系统临时目录名字上的前半段写成 `$CUT…`；评测用例这些仓库里的文件写成 `$REPO`；
用例里拼出来的假令牌（`ghp_…` 这类，假进程的命令行参数会原样记下）写成 `$FAKE_TOKEN`，golden 里不留令牌样子的字面量
（公开导出、出版的泄漏检查会停在上面）。golden 里跑命令之前改过假答案的，先记一步 `{"fakes": {改了的键: 新值}}`（和场景的起点比：`quiet_fakes` 或
`standard_fakes`），这个用户的 uid 写成 `"$UID"`。路径换成占位：假家目录 `~`、假临时目录 `$TMPDIR`、假目录的根 `$FIXTURE`；报告里拿掉每次都不一样的
`ruleSeconds`、`startedWall`，发现和没扫描的按内容排序（顺序不算约定）。
