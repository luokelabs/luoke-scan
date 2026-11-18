# 扫描给 agent 的只读数据（`data/…`）

给自己拼扫描页的 luoke-agent 看（顶层 ADR 0028：主窗口的页面只在 luoke-agent 里定，工具只给原始数据和动作）。
这里只有代号和原始数值（字节、时间、计数、路径、名字），没有 A2UI，没有拼好的句子；页面上放什么、怎么排、怎么说都由 agent 定。
动作照旧是现有的 MCP 工具，见最后一节的动作清单。旧的基础页（`page/overview`、`page/mac`、`page/cleaned`）在搬完之前照旧答。

代码在 `internal/service/data.go`；每个场景读到的真实答复录在 [fixtures/agent/](../fixtures/agent/README.md) 的
`read-data-*.json`（`data-actions` 场景照这些数据点按）。

## 怎么读

和别的资源一样：`resources/read`，`mimeType` 是 `application/json`，`contents[0].text` 是一段 JSON 文字。
配件清单 `packaging/luoke-accessory.json` 的 `capabilities.data` 列着这五个（`["overview", "category", "history", "settings", "usage"]`，
和 `actions` 同一层）：agent 看到它才自己拼扫描的页。

| 资源 | 是什么 |
|---|---|
| `data/overview` | 扫描页：替你自动清了什么、还可以清出多少（按类）、这台 Mac 要注意的、大文件、硬盘、权限和别的几项 |
| `data/category?id=<类>` | 一类的详情：这一类的判断要用的事实，逐个文件 |
| `data/history` | 清理记录：一批一行 |
| `data/settings` | 设置里现有的项，原样给值 |
| `data/usage` | 占地方最多的文件夹：每个多大、近 7 天涨了多少、里面最大的几样 |

- `data/category` 带参数读，写法和工具协议 §4 `pageArgs` 一样：`data/category?id=installer`（值按 RFC 3986 百分号编码）。
  `resources/list` 里登记的是不带参数的 `data/category`。别的资源带了参数答「没有这个资源」（-32002）。
- 只读：读的时候不改用户的任何文件。和读 `page/overview` 一样，会把这一轮的清理方案存下来，`scan_apply` 才认得它的编号。

**约定**

- 时间是 UTC 的 ISO 8601（`2026-10-20T12:00:00Z`）；只有日子的写 `YYYY-MM-DD`（按这台 Mac 的时区，规则就是这样记的）。
- 大小一律是字节（整数）；不知道的是 `null`。计数是整数。
- 路径是绝对路径（样例里换成了 `~`、`$TMPDIR`）。名字（应用、工具、模型、skill）照原样给，可能是中文，但不是句子。
- 没有的值是 `null` 或空数组，键照样在。
- 每个资源都有 `schema`（现在是 `1`）：字段改了含义或去掉才加一；只加新字段不加。

## 类别

`data/overview` 的 `reclaimable` 和 `data/category` 用的「类」，由发现的规则定（清理记录里的每一条也按规则归类）：

| 类 `id` | 是什么 | 规则 | `auto` |
|---|---|---|---|
| `cache` | 缓存 | `cache.*`、`space.ai-model`、`space.ipsw`、`space.xcode-device-support` | `cache` |
| `installer` | 下载文件夹里的安装包 | `leftover.installer` | `installer` |
| `duplicate` | 下载文件夹里在别处还有一份的文件 | `space.duplicates` | `duplicate` |
| `temp` | 临时目录里没删掉的文件夹 | `leak.*` | `temp` |
| `leftover` | 删掉的应用留下的数据、没下完的下载、旧版 Homebrew | `leftover.*`（安装包以外） | — |
| `project` | 很久没动过的项目、项目里能重新生成的构建产物 | `stale.project`、`stale.artifacts` | — |
| `large-file` | 很久没打开过的大文件 | `stale.large-file` | — |
| `startup` | 会跟着电脑一起启动的 | `persistence.*` | — |
| `ai-plugin` | 自己装的 AI skill、对话模板里多了话的本机模型 | `skill.*`、`model.chat-template` | — |
| `install-scripts` | 包管理器装依赖时自动跑脚本（改一行设置关掉） | `pkg.install-scripts` | — |
| `malware` | 病毒库、YARA 认出来的文件 | `malware.*` | — |
| `other` | 以上都不是（现在没有） | | — |

`auto`：这一类是不是不用点就清的四类之一（`cache`、`installer`、`duplicate`、`temp`，和 `scan_autoclean`、
`data/settings` 的 `kinds` 是同一套名字）。只说这一类归哪种自动清，不是说这一类每一项都会自动清：自动清另有更严的规则。

一类里的每一项有 `group`（属于哪一组）、`reason`（为什么可以删，代号）和 `facts`（原因背后的原始事实）：

| 类 | `group` | `reason` | `facts` |
|---|---|---|---|
| `cache` | `tool-cache` | `rebuilds` | `cache`（缓存的编号，如 `pip`）、`tool`（工具名） |
| `cache` | `app-cache` | `app-rebuilds` | `app`（应用名）、`bundleId` |
| `cache` | `logs` | `logs` | `app` |
| `cache` | `model` | `redownload` | `tool`、`model`、`downloaded`（日） |
| `cache` | `ipsw` | `redownload` | `downloaded`（日） |
| `cache` | `device-support` | `newer-version` | `platform`、`version`（这一份的）、`newest`（已有的最新的） |
| `installer` | `installer` | `installed`（对应的应用装着）/ `old-download` | `added`（日）、`days`、`app`（装着的应用）、`appVersion`、`installerVersion`、`sameApp`（文件名和装着的应用完全对得上）、`fromInternet`、`signed` |
| `leftover` | `app-data` | `app-removed` | `bundleId`、`lastChanged`（日）、`places`（几处） |
| `leftover` | `partial-download` | `unfinished` | `lastChanged`（日） |
| `leftover` | `intel-homebrew` | `intel-homebrew` | — |
| `duplicate` | `duplicate` | `copy-kept` | `keep`（留下的那一份的路径）、`copies`（要移走的几份） |
| `temp` | `temp` | `left-behind` | `prefix`、`count`、`first`、`last`（日）、`tool`（认得的测试工具） |
| `project` | `project` | `pushed` | `repos`、`lastCommit`（日） |
| `project` | `build-artifacts` | `regenerable` | `count`（几个文件夹） |
| `large-file` | `large-file` | `not-opened` | `lastOpened`（日）；没打开过的是 `neverOpened: true` 和 `lastChanged` |
| `startup` | `launch-agent` | `program-missing` | `label` |
| `startup` | `launch-agent` | `new` | `label`、`name`、`app`、`program`、`scope` |
| `ai-plugin` | `skill` | 查到的最重的一种（`download-exec`、`exfil`……） | `agent`、`skill`、`scope`、`kinds`（查到的几种） |
| `ai-plugin` | `chat-template` | `template-extra` | `tool`、`model`、`template`（模板文件的路径）、`kinds` |
| `install-scripts` | `install-scripts` | `scripts-on` | `tool` |
| `malware` | `malware` | `signature` | `signature`（ClamAV 的特征名）或 `rule`（YARA 的规则名） |

`facts` 里没有的键就是规则这一轮没查到这件事。以后规则多查了什么，这里加键，不改已有的键。

## `data/overview`

| 字段 | 是什么 |
|---|---|
| `scanned` | 上一轮：`started`、`finished`；还没查过是 `null` |
| `scanning` | 正在查的这一轮：`started`、`checksDone`、`checks`、`fraction`（0 到 1，不知道是 `null`）；没在查是 `null` |
| `autoCleaned` | 最近 7 天不用点就清的，新的在前，一次自动清一项（见下） |
| `reclaimable` | 还可以清出多少，按类（上表的顺序），一类一项（见下）；没有的类不列 |
| `attention` | 这台 Mac 要注意的：`count`、`urgent`（其中急的几项）、`items`（见下）；`count` 是 0 就是正常 |
| `largeFiles` | 很久没打开过的大文件（不会自动清）：`count`、`bytes`。和 `reclaimable` 里的 `large-file` 是同一批 |
| `disk` | 家目录所在的硬盘：`free`、`total`（现在读的）；读不到是 `null` |
| `fullDiskAccess` | `granted` / `denied` / `ask`（和 `permissions` 资源的 `fda` 一样） |
| `autoclean` | 不用点就清开着没有（开着、而且四类没有全部关掉） |
| `skipped` | 上一轮没查成的：`rule`、`reason`（`fda` 要完全磁盘访问、`interrupted` 被打断、`other`） |
| `virusDb` | 病毒库：`version`、`date`（日）；没有是 `null` |

`autoCleaned` 的一项：

| 字段 | 是什么 |
|---|---|
| `batch` | 这次自动清的编号（`auto-<时间>`）：`scan_restore` 的 `id` |
| `at` | 什么时候清的 |
| `bytes` | 一共多大（删掉的缓存加移到废纸篓的） |
| `kinds` | 清了哪几类：`kind`（四类的名字）、`count`、`bytes`、`restorable`（还能放回几项）、`restored`（已经放回几项）；`cache` 还有 `tools`（清了哪些工具的缓存）、`partial`（只清掉一部分的） |
| `restorable` | 这一次还能放回几项（缓存是直接删的，不算） |
| `failed` | 没清成的工具 |
| `unrecorded` | 移到了废纸篓、但没记进清理记录的几项（放不回，要在访达里打开废纸篓找） |

`reclaimable` 的一项（`data/category` 最上面也是这些字段）：

| 字段 | 是什么 |
|---|---|
| `id` | 类 |
| `bytes`、`count`、`files` | 一共多大、几项、几处（一项可以指好几处，比如 25 个临时文件夹是一项） |
| `suggested`、`suggestedBytes` | 默认选了清掉的几项、多大 |
| `auto` | 见上 |
| `facts.groups` | 每一组几项（`{"installer": 5}`） |
| `facts.apps` | 涉及的应用（名字；删掉的应用写 bundle id），排好序 |
| `facts.tools` | 涉及的工具 |
| `facts.appsInstalled`、`facts.appsMissing` | 涉及的应用里装着的、不在这台 Mac 上的各几个 |
| `facts.rebuilds` | 删了会自己重建的几项 |
| `facts.userFiles` | 删了会不会丢用户自己的东西，取这一类里最重的：`none` / `maybe` / `yes` |
| `facts.password` | 要输 Mac 密码才能移走的几项 |

`attention` 的一项：扫描页「要你看看」里列的（风险高的「仅供参考」也算），加上方案里还没处理的急事（病毒）。

| 字段 | 是什么 |
|---|---|
| `finding` | 发现的编号（`scan_ignore` 的 `finding_id`） |
| `rule` | 规则（代号，如 `posture.filevault`、`keyboard.unvouched`、`permission.stale-grant`） |
| `severity` | `low` / `medium` / `high` |
| `urgent` | 是不是急事（和 outbox 的 `security` 一样的判断） |
| `category` | 也能从哪一类里清掉（病毒是 `malware`）；只能看的是 `null` |
| `path`、`reveal` | 在哪；在访达中显示时选中哪里。没有位置的是 `null` |

示例（`fixtures/agent/full-report`，删掉了一部分）：

```json
{
  "schema": 1,
  "scanned": {"started": "2026-10-20T12:00:00Z", "finished": "2026-10-20T12:00:00Z"},
  "scanning": null,
  "autoCleaned": [],
  "reclaimable": [
    {"id": "cache", "bytes": 349175808, "count": 6, "files": 6, "suggested": 6, "suggestedBytes": 349175808, "auto": "cache",
     "facts": {"groups": {"tool-cache": 6}, "apps": [], "tools": ["Bun", "Go", "Xcode", "npm", "pip", "uv"],
               "appsInstalled": 0, "appsMissing": 0, "rebuilds": 6, "userFiles": "none", "password": 0}},
    {"id": "large-file", "bytes": 65011712, "count": 3, "files": 3, "suggested": 0, "suggestedBytes": 0, "auto": null,
     "facts": {"groups": {"large-file": 3}, "apps": [], "tools": [], "appsInstalled": 0, "appsMissing": 0, "rebuilds": 0,
               "userFiles": "yes", "password": 0}}
  ],
  "attention": {"count": 8, "urgent": 2, "items": [
    {"finding": "malware.clamav/000000000003", "rule": "malware.clamav", "severity": "high", "urgent": true,
     "category": "malware", "path": "~/Downloads/eicar-test.com", "reveal": "~/Downloads/eicar-test.com"},
    {"finding": "posture.filevault", "rule": "posture.filevault", "severity": "high", "urgent": false,
     "category": null, "path": null, "reveal": null}
  ]},
  "largeFiles": {"count": 3, "bytes": 65011712},
  "disk": {"free": 182000000000, "total": 494000000000},
  "fullDiskAccess": "granted",
  "autoclean": false,
  "skipped": [],
  "virusDb": {"version": "27000", "date": "2026-10-20"}
}
```

自动清过的一项（`fixtures/agent/autoclean-done`）：

```json
{"batch": "auto-2026-10-20T12:00:00Z", "at": "2026-10-20T12:00:00Z", "bytes": 181489664, "restorable": 23, "failed": [], "unrecorded": 0,
 "kinds": [
   {"kind": "cache", "count": 1, "bytes": 62914560, "tools": ["pip"], "partial": [], "restorable": 0, "restored": 0},
   {"kind": "installer", "count": 1, "bytes": 6291456, "restorable": 1, "restored": 0},
   {"kind": "duplicate", "count": 1, "bytes": 2097152, "restorable": 1, "restored": 0},
   {"kind": "temp", "count": 21, "bytes": 110186496, "restorable": 21, "restored": 0}]}
```

## `data/category?id=<类>`

最上面是这一类的合计和事实（同 `reclaimable` 的一项），另有：

| 字段 | 是什么 |
|---|---|
| `known` | `id` 是不是认得的类；不认得（或没带 `id`）是 `false`，`items` 是空的 |
| `scanned` | 同 `data/overview` |
| `items` | 逐项，大的在前，最多 100 项（见下） |
| `more` | 还有几项没列（最小的那些）。没列的不在页上，`scan_apply` 不发它们就是先不动；`count`、`bytes` 照样算全部 |

`items` 的一项：

| 字段 | 是什么 |
|---|---|
| `plan`、`key` | 这一项在哪份方案里、它的键：`scan_apply` 的 `plan_id` 和 `choices` 的键 |
| `finding` | 发现的编号（`scan_ignore` 的 `finding_id`） |
| `rule`、`group`、`reason`、`facts` | 见「类别」一节 |
| `path` | 这一项是什么（重复文件是要移走的那一份；临时文件夹是 `…/wings-*` 这样的样式） |
| `reveal` | 在访达中显示时选中哪里（临时文件夹是它们所在的文件夹，对话模板是模板文件） |
| `paths` | 清理时会动的每一处，最多 20 处 |
| `pathsMore` | 还有几处没列。清理这一项时动的照样是全部 |
| `bytes` | 多大；不知道是 `null` |
| `suggested` | 默认的选择 |
| `options` | 能选的：`trash` 移到废纸篓、`remove` 删掉（会重建的缓存）、`delete` 删掉（失效的链接）、`clone` 换成克隆、`scripts-off` 关掉自动运行、`keep` 先不动、`ignore` 以后别提 |
| `rebuilds` | 删了会不会自己重建 |
| `userFiles` | 删了会不会丢用户自己的东西：`none` / `maybe`（删掉的应用的数据、推送过的项目）/ `yes`（用户自己的大文件） |
| `app`、`appInstalled` | 对应的应用、它装没装（知道时才有） |
| `password` | 要输 Mac 的密码（系统目录里的；在另一份方案里） |
| `restorable` | 清掉以后能不能用 `scan_restore` 整批放回（直接删的缓存、失效的链接、要密码的、病毒、开机启动项不能） |

示例（`fixtures/agent/data-actions`）：

```json
{
  "schema": 1, "known": true, "id": "installer", "scanned": {"started": "2026-10-20T12:00:00Z", "finished": "2026-10-20T12:00:00Z"},
  "bytes": 6291456, "count": 1, "files": 1, "suggested": 1, "suggestedBytes": 6291456, "auto": "installer",
  "facts": {"groups": {"installer": 1}, "apps": ["Fixtureapp"], "tools": [], "appsInstalled": 1, "appsMissing": 0,
            "rebuilds": 0, "userFiles": "none", "password": 0},
  "items": [
    {"plan": "p-000000000002", "key": "i3", "finding": "leftover.installer/000000000007", "rule": "leftover.installer",
     "group": "installer", "reason": "installed",
     "facts": {"added": "2026-09-30", "days": 20, "app": "Fixtureapp", "appVersion": "2.0", "installerVersion": "2.0",
               "sameApp": true, "fromInternet": true, "signed": true},
     "path": "~/Downloads/Fixtureapp-2.0.dmg", "reveal": "~/Downloads/Fixtureapp-2.0.dmg", "paths": ["~/Downloads/Fixtureapp-2.0.dmg"], "pathsMore": 0,
     "bytes": 6291456, "suggested": "trash", "options": ["trash", "keep", "ignore"], "rebuilds": false, "userFiles": "none",
     "app": "Fixtureapp", "appInstalled": true, "password": false, "restorable": true}
  ],
  "more": 0
}
```

## `data/history`

| 字段 | 是什么 |
|---|---|
| `batches` | 一批一行，新的在前，最多 100 批（清理记录留 90 天） |
| `more` | 更早的还有几批没列 |

一批：

| 字段 | 是什么 |
|---|---|
| `batch` | 编号：点过的方案是 `p-…`，自动清是 `auto-…`；`scan_restore` 的 `id` |
| `auto` | 是不是自动清的 |
| `at` | 这一批最后一条的时间 |
| `bytes` | 一共多大（记录里有大小的加起来；见最后一节「不足」） |
| `count` | 几条（一处一条） |
| `categories` | 清了哪几类：`id`、`count`、`bytes`，按 `id` 排 |
| `deleted` | 直接删掉的几条（缓存、失效的链接，不用放回） |
| `password` | 输了密码移走的几条（放回不在这里做） |
| `restored` | 已经放回的几条 |
| `restorable` | 还能放回的几条（还在废纸篓里；病毒、开机启动项整批放回时不带） |

```json
{"schema": 1, "more": 0, "batches": [
  {"batch": "auto-2026-10-20T12:00:00Z", "auto": true, "at": "2026-10-20T12:00:00Z", "bytes": 181489664, "count": 24,
   "categories": [{"id": "cache", "count": 1, "bytes": 62914560}, {"id": "duplicate", "count": 1, "bytes": 2097152},
                  {"id": "installer", "count": 1, "bytes": 6291456}, {"id": "temp", "count": 21, "bytes": 110186496}],
   "deleted": 1, "password": 0, "restored": 0, "restorable": 23}]}
```

## `data/settings`

| 字段 | 是什么 |
|---|---|
| `autoclean.on` | 不用点就清的总开关开着没有 |
| `autoclean.offSince` | 什么时候关的；开着、或者从没开过是 `null` |
| `autoclean.neverOn` | 从没开过（装好以后默认关着） |
| `kinds` | 四类各自：`kind`、`off`（放回过这一类，以后先问）、`offSince` |
| `ignored` | 「以后别提」的：`finding`、`rule`、`category`、`path`（上一轮还有它时才有）、`at`，新的在前 |

总开关开着、四类全部 `off` 时，`data/overview` 的 `autoclean` 和 `permissions` 的 `auto` 都算关。

```json
{"schema": 1,
 "autoclean": {"on": false, "offSince": null, "neverOn": true},
 "kinds": [{"kind": "cache", "off": false, "offSince": null}, {"kind": "installer", "off": false, "offSince": null},
           {"kind": "duplicate", "off": false, "offSince": null}, {"kind": "temp", "off": false, "offSince": null}],
 "ignored": [{"finding": "space.duplicates/000000000008", "rule": "space.duplicates", "category": "duplicate",
              "path": "~/Documents/report-2026.pdf", "at": "2026-10-20T12:06:00Z"}]}
```

## `data/usage`

占地方最多的文件夹。和基础页 `page/mac`「占地方最多的文件夹」是同一批文件夹、同样的大小、同样的合并办法，
只是不带措辞：一行是什么用 `kind` 和名字说，背后是哪些文件夹用 `paths` 说。代码在 `internal/service/usage.go`。

只读，读的时候不看硬盘：都是 space 规则在各轮里量下来的（每个文件夹每天的大小、下一层子文件夹的大小、文件夹里自己最大的几个文件）。
量的是家目录的直接子文件夹，`Library`、`Library/Caches`、`Library/Application Support`、`Library/Containers`、
`Library/Developer`、`.cache`、`.local/share` 再往下拆一层，加上临时文件夹；不到 1 MB 的不列。

```json
{
  "schema": 1,
  "scanned": {"started": "2026-11-17T12:00:00Z", "finished": "2026-11-17T12:04:10Z"},
  "complete": true,
  "unseen": [],
  "folders": [
    {"kind": "known", "id": "Downloads", "name": null, "holds": null, "bundleId": null, "apps": null,
     "paths": ["/Users/me/Downloads"], "pathsMore": 0, "bytes": 52428800000, "grew7d": 3221225472, "day": "2026-11-17",
     "top": [{"name": "Xcode_26.xip", "path": "/Users/me/Downloads/Xcode_26.xip", "bytes": 9126805504, "dir": false},
             {"name": "old-project", "path": "/Users/me/Downloads/old-project", "bytes": 4294967296, "dir": true}]},
    {"kind": "dev-caches", "id": null, "name": null, "holds": null, "bundleId": null, "apps": null,
     "paths": ["/Users/me/.cache/uv", "/Users/me/Library/Caches/pip"], "pathsMore": 0, "bytes": 8589934592, "grew7d": null,
     "day": "2026-11-17",
     "top": [{"name": "uv", "path": "/Users/me/.cache/uv", "bytes": 7516192768, "dir": true},
             {"name": "pip", "path": "/Users/me/Library/Caches/pip", "bytes": 1073741824, "dir": true}]}
  ],
  "more": 14,
  "listedBytes": 61018734592,
  "measuredBytes": 70866960384
}
```

| 字段 | 是什么 |
|---|---|
| `scanned` | 上一轮什么时候查的，写法同 `data/overview`；还没查过是 `null` |
| `complete` | 上一轮是不是哪里都量了。`false`：上一轮没有完全磁盘访问，`unseen` 里的地方那一轮没量；还没查过是 `null` |
| `unseen[]` | 没量的地方，相对家目录的路径当代号（`Desktop`、`Documents`、`Downloads`、`Music`、`Movies/TV`、`Library/Photos`、`Library/Mobile Documents`、`Library/CloudStorage`、`Library/Containers`、`Library/Daemon Containers`、`Library/Group Containers`）。这些地方以前量过的照样列在 `folders` 里，是哪天量的看那一行的 `day` |
| `folders[]` | 大的在前，最多 10 行 |
| `more` | 没列出来的还有几行 |
| `listedBytes` `measuredBytes` | 列出来的这几行一共多大；量过的（含没列出来的）一共多大 |

**`folders[]` 的每一行**

| 字段 | 是什么 |
|---|---|
| `kind` | 这一行是什么，见下表 |
| `id` `name` `holds` `bundleId` `apps` | 随 `kind` 给，用不上的是 `null` |
| `paths[]` | 这一行背后的文件夹，绝对路径，大的在前，最多 20 个；窗口用它「在访达中显示」。合并的行有好几个 |
| `pathsMore` | `paths` 没列完的还有几个（`bytes` 照样是全部的） |
| `bytes` | 多大 |
| `grew7d` | 近 7 天涨了多少字节：最新一次和 7 天前（或更早）最近的一次量的比，照实给（缩了是负数，不到 1 GB 也给）。合并的行是有得比的那几个文件夹加起来。没有 7 天前的数是 `null` |
| `day` | 最新一次是哪天量的（`YYYY-MM-DD`）；合并的行取最早的那个。上一轮没轮到或没权限量的文件夹，日子比 `scanned` 早 |
| `top[]` | 里面最大的几样，大的在前，最多 5 个：`name`、`path`、`bytes`、`dir`（是不是文件夹；应用、照片图库这类包也算文件夹）。只有一个文件夹的行：它的下一层子文件夹（1 MB 以上）和它自己的文件里最大的 5 个（1 MB 以上）；合并的行：合进来的那几个文件夹。文件夹量过、但升级前没记下文件的，先只有子文件夹，下一次它有改动、重新量时补上 |

| `kind` | 是什么 | 用到的字段 |
|---|---|---|
| `known` | 系统或常见工具起了名字的文件夹 | `id`：相对家目录的路径，当代号（`Desktop` `Documents` `Downloads` `Movies` `Music` `Pictures` `Public` `Applications` `Library/Caches` `Library/Application Support` `Library/Containers` `Library/Developer` `Library/Mail` `Library/Messages` `Library/Photos` `Library/Mobile Documents` `.cache` `.local/share` `.Trash` `.ollama` `.docker` `Library/Group Containers` `Library/Logs` `Library/Saved Application State` `Library/Fonts` `Library/Safari` `Library/Calendars` `Library/Metadata`） |
| `app` | 一个应用或工具存的东西 | `name`：装着的应用用它自己的名字，别的用文件夹的名字（工具名）；`holds`：`data`（数据）或 `cache`（缓存）；`bundleId`：是应用时给。同一个应用的数据散在几个文件夹里的合成一行，数据和缓存分两行 |
| `hidden` | 家目录下的隐藏文件夹，多半是某个工具的 | `name`：去掉开头的点；是装着的应用的 bundle id 时给应用名和 `bundleId` |
| `library` | 资源库里别的东西 | `name`：`~/Library` 下面的路径 |
| `folder` | 用户自己在家目录建的文件夹 | `name` |
| `temp` | 临时文件夹 | 无 |
| `dev-caches` | 开发工具的缓存，合成一行（pip、uv、npm、Homebrew、Xcode 等，名单在 `macDevCaches`） | 是哪几个工具看 `top[].name` |
| `removed-apps` | 已经不在这台 Mac 上的应用留下的数据，合成一行 | `apps`：几个应用；各自的文件夹看 `paths`、`top` |

- 名字是内容不是措辞：应用名、工具名、文件夹名、文件名照原样给；「的数据」「的缓存」这类词由窗口写。
- 这次没有的：点开一行看里面、直接清；一行往下第二层以后的东西。

## 事项和动作结果里的 `data`

顶层 ADR 0028（2026-11-17 改写）：自带的应用只给「是哪一种事、涉及什么、数字多少、什么状态、能做哪些动作和参数」，
句子、标签、按钮上的字由 luoke-agent 写。所以 outbox 的每一件事、每个动作的答复，在原来的卡片和文字旁边多带一份 `data`。
认得 `data` 的 agent 照它画；别的照旧用卡片和文字。两种 agent 都在用的时候，卡片和文字留着。

`data` 里只有代号、编号、数字，和这台 Mac 上的名字（文件名、应用名、工具名是内容，不是措辞）。代码在
`internal/service/itemdata.go`；测试 `itemdata_test.go` 核对它和卡片按钮发的是同一份方案、同样的项。

### outbox 的每一件事：`items[].data`

`type` 说是哪一种。按钮要发的参数都在里面：`plan` 的 `id` 是 `scan_apply` 的 `plan_id`，`finding` 是
`scan_ignore`、`scan_reveal` 的 `finding_id`。

| `type` | 是什么 | 字段 |
|---|---|---|
| `malware` | 病毒库或 YARA 规则认出的文件 | `finding`；`name` 文件名；`place` 在哪个常用文件夹（`downloads` `desktop` `documents` `pictures` `movies` `music`，都不是为 `""`）；`plan` `{id, key}`：移到废纸篓发 `{plan_id: id, choices: {<key>: ["trash"]}}`，移不了为 `null` |
| `startup-new` | 新出现的、会自己启动的程序 | `finding`；`scope`（`user-agent` `login-item` `cron`，或规则给的别的范围）；`submitted` 是开着的应用交给系统运行的（重启后不再自己起来，不在「登录项」里）；`app` 它属于哪个应用；`program` 程序名；`reveal` 能在访达里显示；`stop` `{id, key}`：停掉它发 `{plan_id: id, choices: {<key>: ["trash"]}}`，只有用户自己的 LaunchAgent 有；`settings` 要去系统设置的「登录项」里关（`scan_open_settings {grant: "登录项"}`） |
| `malicious-package` | 用了已知的恶意软件包 | `finding`；`package` 包名；`count`；`more`：`true` 时这一件代表没有逐个列出的其余几个包，`count` 是包的个数，否则 `count` 是这个包用在几处；`reveal` |
| `space-low` | 可用空间不多 | `free` `total` `swap`（字节；没量到的为 `null`）；`caches` 会重建的缓存一共多大；`plan` `{id, choices}`：照建议清掉缓存发 `{plan_id: id, choices}`，没有可清的为 `null` |
| `round` | 这一轮（自动清理了什么、还有什么待处理） | 见下 |
| `needs-access` | 缺一项只有用户能给的权限 | `permission`（清单 `permissions` 里的 `id`，现在只有 `fda`） |

**`round`**：

- `cleans[]`：这张卡片要说的自动清理，新的在前，最多两次。每次：`batch`（`scan_restore` 的 `id`）、`at`；`tools[]` 清了缓存的工具、
  `bytes` 腾出多少、`partial[]` 只清掉一部分的、`failed[]` 没清成的；`moved[]` 移到废纸篓的，每类 `{kind, count, bytes, names[]}`
  （`kind` 是 `installer` `duplicate` `temp` `cache`；`names` 最多三个 `{name, tool}`，`tool` 是留下这个临时文件夹的测试工具，不知道为 `""`）；
  `unrecorded[]` 没记进清理记录的文件名；`restorable` 这一批能放回；`offerStop` 最新的那一次，可以关掉自动清理（`scan_autoclean {on: false}`）。
- `moreCleans`：更早还有几次没在上面列出。
- `decide`：待处理的，没有为 `null`。`trash` `bytes`：照建议能清几项、腾出多少；`caches`：还没删的会重建的缓存几项，
  `cachesBytes`：这些缓存一共多大，也就是「清理 N 项缓存」那一个按钮能腾出的（`bytes` 里缓存的那一部分；`bytes` 多出来的是要在扫描页上点的、
  默认移到废纸篓的那些。0.3.40 以后的版本才有这个键）；
  `plan` `{id, caches[]}` 是它们的方案和键（清理发 `{plan_id: id, choices: {<键>: ["remove"], …}}`），没有为 `null`；
  `cleaned` `freed`：这一轮已经删掉的缓存几项、腾出多少；`toLook`：一共几项待处理；`rest`：其中没有单独一张急事卡片的几项
  （在扫描页上看）；`offerAuto`：自动清理关着、这一轮本来有它能清的（`scan_autoclean {on: true}`）；
  `skipped` `{fda, virusDb, other}`：没查成的各几项。
- `failed[]`：这一轮自动清理完全没清成的工具（上面 `cleans` 里没说到的）。

### 动作的答复：`structuredContent.data`

| 动作 | `type` | 字段 |
|---|---|---|
| `scan_apply` | `applied` | 各种结果各几项：`moved` `removed` `cloned`（`{count, bytes}`：移到废纸篓、删掉缓存、换成克隆）、`links`（删掉的失效链接）、`scriptsOff`（改了设置的包管理器）、`partly` `ignored` `gone` `skipped` `unchanged`；`left[]`：没做成、只做了一部分的每一项和原因（**还是句子**：原因现在没有代号）；`trashed` 有东西进了废纸篓；`restore`：能放回时是 `scan_restore` 的 `id`；`retry` `{plan, choices}`：急事卡片上没做成时再试一次要发的；`unrecorded[]`；`password`：旁边要密码的那份方案还等着；`round`：从这一轮的卡片点的、卡片还留着时，是它现在的 `round` |
| `scan_restore` | `restored` | `back` `left` `before`（放回了、没放回、之前放回过的各几项）；`notes[]` 没放回或放到了别处的每一项和原因（**还是句子**）；`round` |
| `scan_ignore` | `ignored` | `finding`；`undo`；`rule`；`name`（认出的文件的文件名，别的为 `""`） |
| `scan_autoclean` | `autoclean` | `on`；`kinds[]` 以后不问就清的几类；`keptOff[]` 放回过、照旧先问的几类；`round` |
| `scan_now` | `scan-started` | `already`：本来就在查 |
| `scan_reveal` | `revealed` | `path` |
| `scan_open_settings` | `opened` | `what`（系统设置的页，代号）；`activityMonitor` |

出错的答复照旧是 `code`（`not_ready` `stale` `invalid` `failed` `needs_user_action`）加一句话；一句话还没有换成代号。
要密码的那份方案（`scan_apply` 走 `applyAdmin`）、`scan_status`、`scan_findings`、`scan_plan` 的答复还没有 `data`。

## 动作清单

都是现有的工具。会改动东西的（`writes`）要带 `ai.luoke/user-action`（工具协议 §5），没带的答 `needs_user_action`。
答复里的 `structuredContent.card` 是给旧页面的，agent 自己拼页面时不用，点完重读 `data/…`。

| 动作 | 工具和参数 | 改不改东西 | 能不能撤回 |
|---|---|---|---|
| 把选中的移到废纸篓 | `scan_apply`：`plan_id` 是选中项的 `plan`，`choices` 是 `{"<key>": ["trash"]}`，每个选中的一个；没发的项当作先不动。会重建的缓存选项里只有 `remove`（直接删），重复文件还可以 `clone`。要密码的项（`password: true`）在另一份方案里，要另发一次，由本体弹密码框 | 改 | `trash` 能：`scan_restore` 整批放回（编号是 `plan`，`data/history` 里那一批）。`remove`、`delete` 撤不回，删掉的缓存工具会重建。要密码移走的不在这里放回 |
| 这一类以后别再问 | `scan_apply`：同一份方案里这一类每一项 `["ignore"]`；或者每一项各调一次 `scan_ignore` `{"finding_id": "<finding>"}` | 改（只记下，不动文件） | 能：`scan_ignore` `{"finding_id": …, "undo": true}`；记下的在 `data/settings` 的 `ignored` 里 |
| 放回 | `scan_restore` `{"id": "<batch>"}`（`data/history`、`data/overview` 的 `autoCleaned` 里的 `batch`） | 改 | 放回的东西可以再清。放回一次自动清，那几类以后先问（`data/settings` 的 `kinds[].off`） |
| 在访达中显示 | 窗口自己做，选中 `reveal`。旧的 `scan_reveal` `{"finding_id": …}` 照旧在 | 不改 | — |
| 自动清理开关 | `scan_autoclean` `{"on": true / false}` | 改 | 能，再点一次 |
| 现在查一下 | `scan_now` `{}`（另起一轮，查完 `data/overview` 换成新的一轮） | 不改 | — |
| 打开系统设置 | `scan_open_settings` `{"grant": …}` | 不改 | — |

一次 `scan_apply` 只发一份方案里的项。方案的编号由这一轮的发现算出来，同一轮读几次都一样；新的一轮查完以后编号跟着变，
重读 `data/…` 再点。动手前每一项都再核对一遍，查过以后又改过的、已经不在的跳过，答复里说。

## 不足（以后可能改）

- **同一个文件可能在两类里**：比如下载文件夹里一年多没打开过的安装包，既是 `installer` 又是 `large-file`（规则出了两条发现，
  旧页面也列了两次），两类的 `bytes` 加起来会多算。
- **一项指着好几处时，清理记录不记每处的大小**（临时文件夹这类）：`data/history` 那一批的 `bytes` 会少算，可能是 0。
- **`attention` 只给代号**，没有逐项的事实（哪个应用拿着什么权限、哪个程序在看键盘）。
- **「这一类以后别再问」只管现在列出的这些项**：下一轮新查到的同一类还会出现；不用点就清的四类另有 `kinds[].off`。
- **`data/history` 只到批**：不给每一条的编号。病毒、开机启动项整批放回时不带，要单独放回的现在从数据里点不了。
