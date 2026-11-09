# 清理规则评测

顶层 ADR 0016 的 10-27 修订（luokelabs/luoke#9）：四类东西可以不用点就清，事后能放回：
- 会重建的缓存；
- 放了 14 天以上的、已装应用的安装包；
- 下载文件夹里、在别处还有一份的重复文件；
- 测试工具每跑一次留下的临时文件夹：现在只认 Puppeteer、Playwright、Lighthouse 三种的前缀（`AutoPick.knownTemp`）；别的临时文件夹（agent 留下的也是）只报，每次要点。

开启的条件是规则评测覆盖这四类，并且「不该删的误判为 0」。本目录就是这份评测。

## 测的是什么

每个用例搭一个假的家目录（还有它自己的临时文件夹和「应用程序」文件夹），然后：
1. 跑真的规则：`CacheRule`、`InstallLeftoverRule`、`DuplicateRule`、`TempLeakRule`；
2. 把这一轮的发现交给 `AutoPick`，由它挑出可以不点就清的具体文件；
3. 和用例里写的答案对。

- `auto`：必须挑中。漏了只算召回低。
- `keep`：一个都不能挑。另外，挑中了却不在 `auto` 里的，也算挑错。**挑错是硬门槛**：有一个，自动清理就不能开。
- 规则没跑成的用例不算数，测试会失败。

用例照提案第 5 节和 9.4 节写，每类都有一批「看着像、但不该清」的：
- 缓存：工具正在跑（brew 跑起来是它自带的 ruby，Homebrew 装的 yarn 是 yarn.js，Gradle 守护进程是 java，模拟器的后台服务）；缓存的位置是链接；npx 装的工具、下载的模型、Xcode 归档、模拟器设备、Poetry 给项目建的虚拟环境、JetBrains 的缓存（里面有本地历史）、Gradle 的设置、Yarn 2+ 的全局缓存（PnP 项目直接从里面载入）、Deno 的文件夹（应用的本地数据库）、pre-commit 的文件夹（跑 hook 时暂存的改动）这些不在会重建的清单里。
- 安装包：
  - 比已装的新；测试版、rc 这类带字母的版本号；
  - 没满 14 天；
  - 别家的产品（NotionCalendar、Firefox Developer Edition）；
  - 正挂着；是链接；应用不说版本号；
  - 没签名的（隔空投送、信息收到的同名映像）；没有下载标记的（从 U 盘拷来的）；
  - 苹果自家的应用（Keynote、Final Cut Pro）；网页应用的壳（Chrome、Safari 加到程序坞的）；
  - 用户说过「以后别提」的。
- 重复文件：
  - 只在下载里有；
  - 刚下载两天；最近改过；
  - 首尾一样、中间不同；
  - 硬链接；克隆；链接；
  - 归工具管的文件夹里的；在项目里的（克隆的仓库、解压的工程）；
  - 留的那份在 build 一类文件夹里；
  - 用户说过「以后别提」的。
- 临时文件夹：
  - 认不出是哪个工具的；应用自己的；
  - 还在写的；没满三天；
  - 混进去的链接；
  - 浏览器还开着的。

每个「不该清」的用例只让一道关卡起作用。规则自己先拦下的几道（没满 14 天、链接、克隆、同一个文件挑两次），评测碰不到，在 `internal/core/eval_cleanup_test.go` 里直接喂发现测。

## 怎么跑

```sh
go build -o .build/go/luoke-scan ./cmd/luoke-scan
.build/go/luoke-scan eval-cleanup                 # 打分表；挑错一个就退出码 1
.build/go/luoke-scan eval-cleanup --cases 别的.json
python3 -I blackbox/run.py --only evals/cleanup  # 外部测试也跑，和录好的打分表逐字比
go test ./internal/core/ -run Cleanup            # 用例够数、每类都有，放宽了的挑法会被抓到
```

跑一遍约 15 秒。每个用例写几十到几百 MB，放在系统的临时文件夹里，跑完就删。

## 用例怎么写

见 `internal/core/eval_cleanup.go` 里的 `CleanupCase` 和 `CleanupStep`：
- 路径相对假的家目录；`$TMP/` 是它的临时文件夹，`$APPS/` 是它的「应用程序」文件夹。
- `auto`、`keep` 里可以用 `*`。
- 加一种自动清的东西（新的缓存、新的临时文件夹前缀）时，同时加上它「看着像、但不该清」的用例。
