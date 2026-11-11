# 换成 Go：对照表和进度

扫描从 Swift 换成 Go（11-05 定）。外部测试（`blackbox/`，Swift 版录的 golden）287 个场景全部对上，Swift 代码已经删掉；
Swift 版留在 `backup/swift` 分支。这一页留作对照：哪段 Swift 搬到了哪里。

## 怎么对

```sh
go build -o .build/go/luoke-scan ./cmd/luoke-scan
LUOKE_SCAN_BIN=.build/go/luoke-scan python3 blackbox/run.py      # 和 Swift 版录的 golden 比
go test ./...
```

FSEvents 用 cgo，要一个能用的 C 编译器：`PATH` 里第一个 `clang` 不能用时（比如 swiftly 的壳找不到工具链）加
`CC=/usr/bin/clang`。`CGO_ENABLED=0` 也能编，只是变更日志答不出，每轮都当一切都变了（结果一样，`base/two-rounds`、
`cli/quick` 这类靠日志的场景对不上）。

`go.mod` 钉住工具链（`toolchain`），本机旧版的 `go` 会自己下那一版。不加第三方包，只用标准库和 `golang.org/x/sys`（Go 团队的，
要不要算第三方包另定；能不用就不用）。

## 定了的

- **一个程序**：`luoke-scan`。不再有 `luoke-scan-serve` 和 socket：agent 经螺壳本体拿到的标准输入输出跟 `luoke-scan mcp`
  说话（一行一条 JSON-RPC，长连着；外部测试一次一条，读到结尾就答完退出，两种都要认）。
- **不用 SQLite**：扫描自己的数据每张表一个文件，「快照 + 追加日志」：`<表>.json` 是快照，`<表>.log` 一行一批改动（带 crc），
  追加时 `LOCK_SH`、合并成新快照时 `LOCK_EX`；版本不对就当缓存丢掉。beta 2 用户的 `scan.db` 不迁移，直接删（11-05）。
- **cgo 只有三处**：FSEvents（变更日志）、`CGGetEventTapList`（键盘监听）、「重要用途可用容量」（可用空间，含可清除的）。
  签名用 `/usr/bin/codesign`，按 bundle id 找应用用 `mdfind` 再自己扫应用文件夹，Spotlight 属性用 `mdls`，电源用 `pmset -g ps`，
  进程用 sysctl。
- **要密码的一步**交给螺壳本体弹框（框上写螺壳），接口在 luoke-core 的集成 PR 里定；终端里 `system --trash` 照旧 sudo。
- **发行**：扫描仓库打 tag、出 release（不签名的 tar 包，带 ClamAV、YARA、证书、规则、提示词）。螺壳打包时不用这个 tar 包，
  按 release 的 tag 取源码自己编：内部版取最新的 release，beta、RC、正式版取顶层钉的那个（也得是 release 的 tag）；
  luoke-core 的 `app/build_app.sh` 用 `LUOKE_SCAN_SRC` 指的源码跑 `scripts/package_app.py`，编好放进螺壳.app，和别的一起签名、公证。
- **数据目录**：一律 `~/.luoke-scan`（`--this-mac`，以及不给 `--data` 的 `report`），螺壳里的和单独装的命令行版一样；
  开发和测试用 `--data` 另指。
- **提示词**：开发版从程序往上找仓库的 `prompts/`（最多六层，和 Swift 一样）；正式版用编在程序里的那份（`assets.go`，
  和 `freshclam.conf`、ClamAV 根证书一起）：不管程序放在哪，起它之前核的那个签名都盖住它们。0.3.0 起扫描打进螺壳.app
  （`Contents/Helpers`），不生成 .app。

## 对照表

| Swift | Go | 状态 |
|---|---|---|
| `ScanCore/Finding.swift`、`Context.swift`（格式、哈希、Facts） | `internal/core/report.go`、`format.go`、`facts.go` | 完成 |
| `luoke-scan/main.swift` | `cmd/luoke-scan/main.go` | 完成 |
| `ScanCore/Fixture.swift`（`Fakes`、`Layout.rules`） | `internal/core/fixture.go`（只读 `fakes.json`；造假目录归 `blackbox/fx.py`） | 完成 |
| `ScanCore/Store.swift` | `internal/core/store.go`（快照 + 追加日志） | 完成 |
| `ScanCore/Scanner.swift`、`Walk.swift`、`ChangeJournal.swift`、`Proc.swift`、`Signature.swift`、`Apps.swift` | `internal/core/…`；变更日志 `internal/core/journal.go`，cgo 只在 `fsevents_darwin.go` | 完成 |
| `ScanCore/VirusDB.swift`、`ClamAVCerts.swift` | `internal/core/virusdb.go` | 完成 |
| `ScanCore/Rules/*.swift`（25 条） | `internal/core/rule_*.go` | 完成 |
| `ScanCore/Skill*.swift`、`AgentFiles.swift`（38 处前后查找的正则要改写） | `internal/core/skill*.go` | 完成 |
| `ScanCore/*Eval.swift` | `internal/core/eval_*.go` | 完成 |
| `ScanCore/ModelPrompt.swift`、`Explain.swift`、`Identify.swift`、`SkillReview*.swift`；`ScanService/ModelTasks.swift` | `internal/core/model*.go`、`explain.go`、`identify.go`、`skillreview.go`、`eval_skillreview.go`；`internal/service/hub.go`、`hubtask.go` | 完成；`model/`、`evals/make-skill-evalset` 过；请求体和 bench 逐字节比（`go test`） |
| `ScanService/*.swift` | `internal/service/*.go` | 完成 |
| `ScanService/Admin.swift`、`luoke-scan-admin` | `internal/service/admin.go`、`adminapply.go`、`elevate.go`、`host.go`；`cmd/luoke-scan-admin` | 完成 |
| `ScanSocket/*`、`luoke-scan-serve` | 不要了（本体每个请求起一次 `luoke-scan mcp`） | 完成 |

## 顺序

1. 骨架：格式函数、报告、命令行、假目录模式、一轮不跑规则 → `base/empty`、`cli/version`、`cli/usage`。
2. 数据层（快照 + 追加日志）、病毒库更新 → `rules/malware/db-*`。
3. 规则一条一条换，每换一条对上它的 `rules/<规则>/`。
4. 服务那层：MCP、outbox、卡片、方案、放回、自动清、调模型 → `mcp/`、`model/`。
5. 其余命令、评测 → `cli/`、`evals/`。
6. 性能和 Swift 版比（`bench/perf.py`），三处 cgo 真机验，发行流程，core 的集成 PR。

## 搬规则的规矩

- **一条规则一个文件** `internal/core/rule_<名字>.go`，在 `init()` 里 `Register("<规则 id>", NewXxxRule)`；顺序由 `rules.go` 的
  `RuleOrder` 定（和 Swift 的 `Scanner.defaultRules` 一样）。
- **规则是一个结构体**：要问这台 Mac 的地方（进程、系统命令、Spotlight、launchctl、签名……）做成导出的函数字段，nil 就用真的。
  `NewXxxRule(l *Layout, f *Fakes)`：`l == nil` 是这台 Mac；不是 nil 时照 Swift 的 `Fixture.Layout.rules(_:)` 把这些换成 `f` 的
  答案、只看假目录自己的文件夹（`SystemLibrary`、`usr-local`、`etc`、`Trash`……），门槛照那里调低。
- **问这台 Mac 用命令行**（`/usr/bin/codesign`、`mdfind`、`mdls`、`pmset`、`launchctl`、`/usr/bin/sqlite3 -readonly -json`……），
  不写 cgo：cgo 只留 FSEvents、键盘监听、可用容量三处，由主线程那边写；要用到的先留函数字段和 TODO。
- **自己的数据**用 `NewTable[T](store, "<表名>", 版本)`（`store.go`：`Load`、`Apply`、`Replace`）。增量照 Swift 用
  `BeginIncrement`（`journal.go`）：表里记事件号、inode、真量的时间，日志说没变、没过 `MaxReuse` 的沿用；测试换 `JournalSource`。
- **输出要一字不差**：中文照抄 Swift 的；Swift 数字符（`count`、`prefix`）的地方用 rune；大小用 `FormatBytes`；日期用 `ISODay`
  （本机时区）、`ISOTime`；Go 的 map 没有顺序，凡是会影响输出的都排序，排法和 Swift 一样；列目录用 `Children`（文件系统给的顺序，
  和 Swift 的 `contentsOfDirectory` 一样），走树用 `Tree`。
- **正则**：Go 的 RE2 没有前后查找，Swift 里用了的要改写成别的判断，行为不变（skill 和说明文件的检查另有 `eval-*` 对照）。
- **怎么对**：`go build -o .build/go/luoke-scan ./cmd/luoke-scan && LUOKE_SCAN_BIN=.build/go/luoke-scan python3 blackbox/run.py --only rules/<规则 id>`，
  这条规则的场景全过才算搬完。不改 golden、不改 Swift。几条规则共用的帮手各有归属：应用和 bundle id（`apps.go`）归应用组，
  进程表（`procs.go`）归系统组，skill 和说明文件（`skill*.go`、`agentfiles.go`）归 AI 文件组，git（`git.go`）归空间组；
  要用别组的、那组还没写的，先在自己文件里写个小的私有版本。
