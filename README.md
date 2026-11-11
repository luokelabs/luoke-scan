# 螺壳扫描

*它为这台 Mac 加护：拂去你不会想念的，无一不可复还。*

简体中文 | [English](README.en.md)

在你不用电脑的时候查一遍这台 Mac：空间被什么吃掉了、哪些能放心清；有没有可疑的常驻程序、权限、扩展和病毒。每一条都说清依据，删不删由你点，清掉的都能放回。是不是垃圾、风险多高由确定的规则判断，本机模型只负责讲成人话；什么都不离开你的 Mac。

> **English summary** ([full English README](README.en.md)). Luoke Scan (螺壳扫描, `luoke-scan`) checks your Mac while you are away: what is eating disk space and what can safely go, and what looks suspicious — things that start by themselves, stale privacy grants, browser extensions, AI tool configurations and skills, malware (ClamAV and YARA). Deterministic rules decide what is junk and how risky something is; a local model only explains. Nothing is deleted until you click, except four narrowly defined kinds you can turn off; everything but rebuildable caches and dead links goes to the Trash and can be put back. Nothing leaves the Mac except a daily virus-database download. Part of [Luoke](https://github.com/luokelabs/luoke) by Luoke Labs; in closed beta, first shipped with beta 2; the interface is Chinese for now.

## 它是什么、在螺壳里的位置

螺壳是螺壳实验室（Luoke Labs）出品的一组本地 AI 工具，螺壳扫描是其中照看这台 Mac 本身的应用。它只管「查」和「按你点的去清」：什么时候查由螺壳（[luoke-core](https://github.com/luokelabs/luoke-core)）安排在你不用电脑的时候，讲解用的本机模型也由螺壳提供；要你决定的事交给螺壳，由它挑时机用卡片告诉你；清理这类「发生了什么」写进各应用共用的螺壳记忆（[luoke-mem](https://github.com/luokelabs/luoke-mem)）。整体分工见顶层仓库 [luokelabs/luoke](https://github.com/luokelabs/luoke)，各组件的介绍见[系统文档](https://luokelabs.github.io/luoke-atlas/)。

## 现状

- **封闭测试中**，第一次随 beta 2 提供（版本见 [`packaging/luoke-accessory.json`](packaging/luoke-accessory.json)，规则包的版本见 `luoke-scan version`）。
- **系统**：Apple 芯片（M1 起）、macOS 26.2 以上，内存 16 GB 起，推荐 32 GB 以上；这是螺壳的要求。螺壳扫描本身也要 macOS 26.2，只有 Apple 芯片版。
- **怎么跑**：每天最多一轮，只在接着电源、你不用电脑的时候；你一回来就停在做完的那一步，下一轮接着查。第二轮起只重看变过的地方（按 macOS 的文件改动记录）。以后还会在两轮之间每隔几分钟看一眼新下载的文件，只扫病毒，用电池、开着低电量模式或内存紧张时不看（要等螺壳给它一个起的入口，现在还没有）。
- **本机模型**：讲解、认文件夹、看 AI skill 三件事用螺壳提供的模型；螺壳的模型没开时照样查、照样出结果，只是少了这几段说明。
- **界面**：中文。

## 怎么用

到 [luoke.ai](https://luoke.ai) 下载螺壳，在螺壳的「应用」里开启螺壳扫描就行。病毒扫描器（ClamAV、YARA）随包带着，还没有病毒库时，第一轮先把它下载下来再查，不用自己装。

之后不用管它：每天查一遍，要你决定的事螺壳会用卡片告诉你，清理方案列出删什么、多大、为什么，你点了才做；全部结果和清理记录也能在螺壳里看（「概览」「清理记录」）。想查得全，在「系统设置 → 隐私与安全性 → 完全磁盘访问」里给「螺壳」打开（可选，见下面「数据和隐私」）。

## 它查什么

**空间**

- **空间去向和增长**：家目录、`~/Library` 几个数据目录和临时目录每天记一次大小，每天多 1 GB 以上的指出来；可用空间不够时提醒（附交换文件多大）。
- **会重建的缓存**：pip、SwiftPM、Go、Cargo、Bun、uv、npm、Homebrew、Yarn、CocoaPods、Gradle、Poetry、node-gyp、Composer 的缓存，Xcode 的 DerivedData、文档缓存和跑测试用的模拟器，模拟器的缓存，Corepack 下载的包管理器。删了工具用到时会自己重新下载或生成，不丢你的东西。
- **应用的缓存和日志**：装着的应用放在 `~/Library/Caches` 里的缓存，编辑器、聊天软件这类 Chromium 系应用的缓存文件夹（设置、登录和数据不动），`~/Library/Logs` 里的日志和崩溃报告，大的列出来。账号、钥匙串、密码管理器、钱包、VPN、输入法、安全和设备管理软件、离线音乐、网盘、邮件、照片和 Apple 自己的一律不列。都要你确认，移到废纸篓；查过以后应用又写过的，这次不清。
- **临时文件夹里越积越多的**：同一个前缀的临时文件夹成批没删（常见是测试每跑一次留一份），给出个数、大小、每天多少，好从源头修。
- **卸载残留**：已经卸载的应用留在 `~/Library` 和系统 `/Library` 里的数据，下载文件夹里早就装好了的安装包、没下完的下载，系统升级挪出来的旧文件，Apple 芯片的 Mac 上没人用的旧 Intel 版 Homebrew。名字像钱包、密码库、密钥、VPN 配置的只提示，不建议删。
- **很久没动的**：半年没动的项目（先查 git：有没推送的提交、没提交的改动、stash、没有远程的，只提示并写清删了会丢什么），老项目里能重新生成的依赖和构建产物，一年没打开过的大文件（Spotlight 记的）。
- **重复文件**：下载、桌面、文稿、影片、音乐、图片里内容完全一样的大文件；APFS 克隆和硬链接不算（不多占空间）。可以移到废纸篓，也可以换成克隆：几份都留着，不再多占空间。
- **系统层**：Time Machine 的本地快照留了两天以上、容器和虚拟机的磁盘（Docker、OrbStack、colima、Podman、lume）、AI 工具下载的模型（Hugging Face 的共用存储照文件实际占的算）、装完系统留下的恢复镜像（`.ipsw`）、Xcode 的旧设备支持文件、归档和模拟器。

**安全**

- **会自己启动的程序**：LaunchAgents 和 LaunchDaemons、应用登记的后台程序和登录项、crontab、shell 配置加进 PATH 的文件夹；指向已经不存在的程序、签名对不上、系统级任务的程序你自己就能换掉的。**上一轮以后新出现、没人担保的**（没签名、临时签名、脚本、放在你能改的位置）当急事报。
- **别的启动方式**：往别的程序里注入动态库的环境变量、授权插件、登录钩子、终端每开一个窗口运行的命令、iTerm2 的自动运行脚本、periodic 脚本。
- **最近装的应用**：最近 30 天放进「应用程序」的，签名坏了、没签名、没公证的，附上是哪个程序下载的。
- **进程**：程序文件已经删了还在跑的、同一个程序成批堆在一个父进程下的、父进程没了还跑了很久的。
- **键盘监听**：哪些程序在监听所有按键，没人担保的单独报。
- **对外露出**：在本机以外的地址上监听的端口，正在运行的命令行里带着的密码和令牌，`~/.ssh` 的权限、没有口令或算法太弱的私钥。
- **明文凭据和散落的密钥**：工具明文存的令牌和密码（`.git-credentials`、`.netrc`、`.npmrc` ……），下载、桌面、文稿里的私钥、证书包、云服务密钥。只记位置和种类，不存值。
- **浏览器扩展**：能读写所有网站的、被策略强装的、不是从商店装的扩展，扩展能启动的本机程序（Chromium 系浏览器和 Firefox；不看 Safari）。
- **AI 工具**：MCP 配置里会启动哪些服务器、配置里有没有明文密钥；本机装的 AI skill（带 `SKILL.md` 的文件夹）里有风险的写法：读密钥往外发、从网上下载直接运行、让自己开机启动、改 AI 的设置和记忆、藏起来的文字……（见 [docs/skills.md](docs/skills.md)）。
- **依赖的安装脚本**：项目里和全局装的 npm 包的 `preinstall`、`install`、`postinstall` 和它们运行的文件，项目虚拟环境里从源码装的 Python 包的 `setup.py`：读密钥往外发、下载就运行、解开藏起来的代码运行、跑找密钥的工具、往代码仓库推工作流、用你的令牌发布包、让东西开机启动。按规则报，要确认，不当急事；编译原生模块、下载自己的预编译程序这类正经做法不报（见 [docs/install-scripts.md](docs/install-scripts.md)）。
- **权限授予**：应用已经卸载了，还拿着完全磁盘访问、辅助功能、录屏这些权限。
- **包管理器的安装脚本**：用着的 npm、pnpm、Yarn、pip、uv，装包时会不会让依赖跑它自带的脚本（`postinstall` 这类，Python 源码包的 `setup.py`）。只认在磁盘上找到的版本（npm 12、pnpm 10、Yarn 4.14 起默认就不跑；装着几份的按最新的那份算），只读你自己的配置（`~/.npmrc`、`~/.yarnrc.yml`、`pip.conf`、`~/.config/uv/uv.toml`、pnpm 的全局配置），不看项目里的。每个工具一条，要确认；同时列出已装的依赖里哪些真要跑脚本、以后怎么单独放行，并建议让新版本晚一天再装（只建议，不替你改）。
- **基础设置**：FileVault、防火墙、SIP、Gatekeeper、锁屏、自动更新、远程登录和各种共享、隔空投送对所有人、自动登录、别人加进来的根证书、XProtect 很久没更新。只报不好的。
- **依赖里的已知恶意包**：项目的锁文件（`package-lock.json`、`npm-shrinkwrap.json`、`pnpm-lock.yaml`、`yarn.lock`、`bun.lock`、`uv.lock`、`poetry.lock`、`Pipfile.lock`、`Cargo.lock`）和全局装的包（npm 的全局目录：每个包和它自己 `node_modules` 里各个包的 `package.json`，只取名字和版本；pipx、uv tool、cargo install；bun、pnpm、yarn 的全局锁文件），和本机的恶意包名单（OSV 里 `MAL-` 开头的条目，OpenSSF 的 malicious-packages）按「包名 + 版本」比对；名单写着「所有版本」的也算。从 git、本地文件、别的网址装的不算（名字一样也不是那个包），测试数据和示例文件夹里的锁文件不看；从公司自己的源装的同名包照报，写明来自哪里。只读包的名字和版本，不打开包里的代码；比对在本机做，用了哪些包不出这台 Mac。用了名单上的包当急事报，写清怎么办（删掉 `node_modules` 或虚拟环境、换到名单外的版本，装过就把令牌和钥匙都换掉），不替你删项目里的东西。名单现在要自己导入（`luoke-scan malicious-import <OSV 的 JSON、文件夹或 .zip>`，不联网；每次导入加进原有的名单，可以一个生态一个生态地导）；同一个包用在很多处只报一条，列出用到它的地方；没导入过名单时这一项不查，也不提。
- **病毒**：ClamAV 和 YARA（加上 macOS 自带 XProtect 的 YARA 规则）扫最近 30 天下载的文件、后台任务要运行的程序、正在运行的程序（node、python 这类解释器跑的脚本也算，比如 node_modules 里的；macOS 自带的不扫）、AI skill 里的文件；只扫新的和变了的。病毒库超过 14 天没更新会提醒，照样扫。

每条发现带一个结论——**放心删**（只有会重建的缓存）、**要确认**、**仅供参考**——和依据：大小和增长、时间、签名、git 状态、规则名和版本、病毒库的版本和日期。某一项没查成（扫描器不在、超时、没有权限），就写成「没扫描」并说明原因，不当成没有问题。

**本机模型做什么**：把卡片上要你看的发现讲成人话；给一直在涨的文件夹、卸载应用留下的数据认个名字（只看名字、大小、文件个数这些，不打开文件）；对规则报了的 AI skill，说它实际做的和它自己说的对不对得上。这些都只附在发现下面，不改结论和轻重；显示之前再核一遍，带网址、命令、编出来的数字，或者替什么东西打包票的，一律不显示。

## 安全承诺

- **规则判断，模型只讲**：是不是垃圾、能不能删、风险多高，都由确定的规则决定，同样的情况每次结论一样。
- **查的时候只读**：一轮扫描不改任何东西。
- **你点了才清**：清理只执行螺壳扫描自己出过、你在卡片上点过的方案；执行前逐项再核一遍（还是那个文件、不是链接、没变过）。会改动东西的请求，没有你的点按一律拒绝。
- **打开以后，四类不用点就清，能放回、能关**（默认关，你点了「打开自动清理」才开）：会重建的缓存（直接删）；已经装好了的应用、放了 14 天以上的安装包；下载文件夹里、别处还有一份的重复文件；测试工具（Puppeteer、Playwright、Lighthouse）留下的临时文件夹（这三类移到废纸篓）。只在每天定时的那一轮做，每次都告诉你；你放回过的那一类以后不再自动清，也可以整个关掉。缓存由螺壳扫描自己删，不跑各工具自己的清理命令。这四类的挑法有专门的评测，挑错必须是 0。
- **删除都移到废纸篓，能放回**：清掉的都移进废纸篓、记进「清理记录」，清空废纸篓之前能一键放回原处（原处有同名的就放在旁边）。例外只有两种删了不丢东西的：会重建的缓存（你点的和自动清的都一样，删了马上腾出空间），和旧 Intel 版 Homebrew 留下的失效链接，这两种直接删、放不回。要密码移走的系统目录里的东西也在废纸篓里，但归系统所有，要在访达里拖回（会要密码）。
- **改设置只加一行、能放回**：包管理器的「改成不跑」只往你自己的用户配置末尾加一行（还没有 `pip.conf` 时新建一个，多一行 `[global]`；项目里的配置不碰），改之前核对还是查的那个文件、路上没有链接（配置本身是链接或硬链接、路上的文件夹是链接的不改，只告诉你加哪一行）；新的一份写好以后和原来那份对换，任何时候那个位置上都是一份完整的配置，对换时正好有程序在改它就换回去、不动；原来那份移到废纸篓、记进清理记录，放回时再对换回来；放回之前你又改过的，留着你的，原来那份放在旁边；原来那份已经不在废纸篓里的，改过的那份留着不动。
- **要密码的只做你确认的那几项**：系统 `/Library` 里的卸载残留、旧的 Intel 版 Homebrew 要管理员权限。你点了以后弹 macOS 自己的密码框，一次一授权，不装常驻的管理员程序；以管理员身份运行的是单独签名的 `luoke-scan-admin`，运行前先核对它的签名，每一项重新判断一遍，也是移到废纸篓。
- **别的账户的东西不碰。**
- **不打扰**：不弹通知、没有菜单栏图标；要说的事交给螺壳，由它挑时机。
- **什么都不离开你的 Mac**：见下一节。

## 数据和隐私

**只在本机**：扫描、判断、讲解都在你的 Mac 上做；扫描结果、文件内容不上传，螺壳没有服务器。

**读什么**：大多数检查只看元信息（名字、大小、时间、属主、签名、链接数），不打开文件。要读内容的只有：重复文件（算 SHA-256，记住哈希，没变的不再读）、项目和全局装的包的锁文件、全局装的 npm 包的 `package.json`（都只取包名和版本）、明文凭据和散落的密钥（只读小文件的开头）、AI skill（读进内存，查完就放掉）、依赖的安装脚本（只读包的 `package.json` 和安装钩子运行的文件，不扫整个 `node_modules`；记住读过的，没变的不再读，不记脚本内容）、要查的配置文件（后台任务、浏览器扩展、MCP、shell 配置），以及病毒扫描（ClamAV 和 YARA 读要扫的文件）。内容不写日志、不进记忆、不进卡片；找到的密码、密钥、令牌只记位置和种类，不存值。交给本机模型的：讲解给的是发现的结论、标题、位置、大小和依据；认文件夹只给元信息；看 skill 给的是它的名字、说明和截短的内容（整个不超过 6000 字），模型在螺壳里运行。

**什么时候联网**（照代码核过，螺壳的联网清单里扫描那一节）：

- **病毒库**：每天最多一次，由 freshclam 从 `database.clamav.net` 下载 ClamAV 的病毒库（freshclam 默认还会先查一下 `current.cvd.clamav.net` 的 DNS 记录，看有没有新库）。只下载，不上传任何东西；新库每个文件用 ClamAV 的根证书校验过才换上（证书随包带着），失败就留着旧库。
- **恶意包名单不下载**：只从你给的本机文件导入（`luoke-scan malicious-import`），比对也只在本机做。
- **别的都不联网**：git 只在本机读（不 fetch）；模型和记忆都经本机的螺壳；给螺壳 agent 用的接口不开 socket、不开网络端口：螺壳每个请求起一次扫描程序，经它的标准输入输出说话。
- 你在卡片上点「在访达里显示」「打开设置」时，由 macOS 打开访达或系统设置。

模型的输出不会让程序去连任何地址，也不会让它删什么。

**数据放在哪**：`~/.luoke-scan/`，只有你的账户能读（700），不进 Time Machine 备份。

- 不用数据库：每类记录一份快照（`<名字>.json`）加一份之后的改动（`<名字>.log`，一行一批、带校验），`<名字>.lock` 是它的锁。有文件夹大小的历史（`sizes`）、量过和查过的结果（`measured`、`project_state`、`leftover_state`、`temp_entries`，下一轮只重看变过的）、重复文件的哈希（`file_hashes`）、扫过病毒的文件（`malware_scanned`）、见过的会自己启动的程序（`seen-persistence`）、模型的答复（`model_answers`）、病毒库的状态这类零碎（`meta`）。都是缓存：读不了的整个丢掉，下一轮重建
- `last-report.json`：上一轮的结果
- `progress.json`：正在跑的这一轮查到哪了（跑完就删）
- `agent-state.json`：告诉过你什么、你说不用管的、不用点就清的开关
- `cleaned.jsonl`：清理记录（什么移进了废纸篓、原来在哪），放回就靠它
- `plans/`：卡片上的清理方案
- `vitals.json`、`vitals.log`：之前一轮看到的各程序用了多少处理器时间（只记进程号、启动时间、秒数和那一轮的时间；不到 30 分钟的不换成新的），之后的轮次比一比哪个一直占满处理器
- `clamav/`、`clamav-quick/`：病毒库
- `malicious-packages.txt`：导入的恶意包名单（生态、包名、MAL 编号、受影响的版本，开头写着名单的日期）

写进螺壳记忆的只有「发生了什么」：你清了哪一类、说了哪一类不用管、自动清了什么、病毒提醒后来怎样、开没开不用点就清；不写路径、文件夹内容和哈希（病毒提醒只带文件名）。

**完全磁盘访问是可选的**：它授权给螺壳本身（顶层 [ADR 0021](https://github.com/luokelabs/luoke/blob/main/docs/adr/0021-full-disk-access-belongs-to-luoke.md)），螺壳起的扫描程序用这一份授权，你不用另外给螺壳扫描。没有它时，扫描一律不看 macOS 会弹框询问的地方（桌面、文稿、下载、iCloud 云盘、别的应用的数据），这几项写成「没查」并说明原因，不当成没有问题；其余照常查。打开以后，下载里的病毒、重复文件、散落的密钥、别的应用的残留、过期的权限授予这些才查得全。螺壳会在有一项因为它没查成时告诉你，打开的地方是「系统设置 → 隐私与安全性 → 完全磁盘访问」里的「螺壳」。

## 安全设计

- **两个程序**：`luoke-scan` 做扫描和清理，从不开 socket、不监听网络：给螺壳 agent 的工具（MCP）由螺壳本体起 `luoke-scan mcp`，经它的标准输入输出说话；`luoke-scan-admin` 只在你在螺壳的密码框里输入密码以后，以管理员身份做那一次删除。
- 要密码的那一步只由螺壳本体弹框：扫描只把「哪份方案的哪几项」交给本体，root 跑的命令由本体拼——它先把自己包里的 `luoke-scan-admin` 拷进只有 root 能写的目录、在那里核对签名（螺壳的开发者签名），再用空环境跑；扫描说的话不进那条命令。在终端里也可以自己做（`luoke-scan system`，经 sudo，同样先核对签名）。
- 外部命令（git、clamscan、yara……）都带超时。扫描（定期的和 agent 叫的那一轮）和更新病毒库一开始就把自己降到低优先级（CPU 和读写磁盘都让着你在用的程序），它们起的外部命令跟着低；给 agent 答话的 `luoke-scan mcp`（你点了以后执行方案也是它）不降。git 关掉仓库配置里会运行程序的项（fsmonitor、hooks 这些），被扫描的仓库没法借 git 运行它自己的程序。
- 装好的 .app 只认 `--this-mac`，不收开发用的参数，扫描器只用包里带的那几个。
- 随包的第三方程序和库只是单独的进程，螺壳扫描不链接它们，见 [NOTICE](NOTICE)。

## 从源码构建和开发

适合开发者；普通用户请用上面的螺壳。

需要：Apple 芯片的 Mac、macOS 26.2 以上、Go 1.25 以上（`go.mod` 钉着工具链，旧一点的 `go` 会自己换成那一版）、Xcode 的命令行工具（cgo 要 C 编译器：FSEvents 变更日志、键盘监听、可用容量三处用到 macOS 的框架）。第三方包只有 Go 团队的 `golang.org/x/sys`。打包成 .app 另外要 Homebrew 的 `clamav` 和 `yara`（[`scripts/package_app.py`](scripts/package_app.py)），开发和测试不需要。

```bash
git clone https://github.com/luokelabs/luoke-scan.git
cd luoke-scan
go build -o .build/go/luoke-scan ./cmd/luoke-scan
go test ./...
python3 -I blackbox/run.py      # 从外面测：几百个场景，几分钟
```

PATH 上的 `clang` 用不了时（比如被别的工具链的垫片占了），命令前加 `CC=/usr/bin/clang`。

测试只用生成的假用户目录和假的扫描器（假 clamscan、freshclam、sigtool、yara 都是 shell 脚本），只在临时目录里读写，不碰你的家目录、不联网、不弹框。外部测试（[`blackbox/`](blackbox/README.md)）只经命令行跑 `luoke-scan`，和录好的答案逐字比对。

在一个埋好答案的假用户目录上试命令行：让外部测试留下它造的假目录，再对它跑：

```bash
python3 -I blackbox/run.py --only base/two-rounds --keep             # 打印假目录在哪
.build/go/luoke-scan scan --fixture <假目录> --clock 2026-10-20T12:00:00Z   # 查假目录：进程、系统设置这些也是假的
.build/go/luoke-scan report --data <假目录>/data                        # 按放心删、要确认、仅供参考列出来
```

开发时一律用自己的假家目录和数据目录：`--home <假目录> --data .dev/<名字>`（`.dev/` 不进 git），从不碰真实的家目录和 `~/.luoke-scan`。`--home` 只换家目录，进程、系统设置这些仍读这台 Mac 的（只读）；`--fixture` 连这些也换成假的。`luoke-scan` 不带参数会列出所有命令。

### 评测

```bash
.build/go/luoke-scan eval-cleanup       # 不用点就清的四类：72 个用例，挑错必须是 0
.build/go/luoke-scan eval-skills        # AI skill 的检查：33 个恶意、33 个正常的合成 skill
.build/go/luoke-scan eval-agentfiles    # 给 AI 看的说明文件（AGENTS.md、CLAUDE.md……）的检查：13 个恶意、13 个正常
python3 bench/test_checks.py               # 评测程序自己的检查对不对，不用模型
```

三个生成任务（讲解 explain、认文件夹 identify、看 skill skills）的评测集在 `bench/evalsets/`，都是合成的；提示词在 `prompts/`，扫描发给模型的请求和评测程序发的逐字节一样。任何开在 127.0.0.1 上、OpenAI 兼容的本地模型服务都能测：

```bash
python3 bench/run_eval.py --endpoint http://127.0.0.1:<端口> --model <模型名> --label <标签> --out .dev/evals                # explain、identify
python3 bench/run_eval.py --endpoint http://127.0.0.1:<端口> --model <模型名> --task skills --label <标签> --out .dev/evals   # skills
```

每条有确定的检查，全部通过才算过；硬性条目没全过退出码 1。之前的结果（`bench/results/`，2026-10-23，一台 M3 Ultra 经本机端点、温度 0，每条 3 遍都过才算过）：

| 模型 | explain | identify |
|---|---|---|
| Qwen3.5-9B 4-bit | 31/32，硬性 13/13 | 29/30，硬性 8/8 |
| gemma-4-26B 8-bit | 29/32，硬性 13/13 | 29/30，硬性 8/8 |

skills 的结果和提示词改了几版的经过见 [docs/skills.md](docs/skills.md)。

## 文档

- [docs/skills.md](docs/skills.md)：查本机 AI skill 的设计（查哪里、十类检查、隐私、语义检查和它的评测）
- [docs/install-scripts.md](docs/install-scripts.md)：查依赖的安装脚本（查哪里、跟到哪些文件、报什么不报什么、上限、量误报）
- [evals/cleanup/README.md](evals/cleanup/README.md)：不用点就清的四类的评测，每类「看着像、但不该清」的用例
- [fixtures/agent/README.md](fixtures/agent/README.md)：给 agent 的场景样例：几种处境下扫描真实的答复（outbox、卡片、基础页、权限），`scripts/record_agent_fixtures.py` 录的
- [evals/skills/README.md](evals/skills/README.md)：skill 检查的合成评测集
- [bench/](bench/)：生成任务的评测（`run_eval.py`、`evalsets/`、`results/`）和性能基准（`perf.py`，用法写在文件开头）
- [prompts/](prompts/)：三个生成任务的提示词（一个任务一组文件）
- [CONTEXT.md](CONTEXT.md)：术语
- [scripts/package_app.py](scripts/package_app.py)：打包、签名和核对，开头写了包里有什么
- 螺壳整体的分工和跨组件的决定：顶层仓库 [luokelabs/luoke](https://github.com/luokelabs/luoke) 的 `ARCHITECTURE.md` 和 `docs/adr/`（0013 本机就是边界、0016 替用户做事、0018 模型归螺壳、0021 完全磁盘访问给螺壳）

## 许可、安全、贡献

- 许可：Apache-2.0，见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。版权所有 © 螺壳实验室 Luoke Labs。随包的 ClamAV 等第三方组件各按自己的许可，见 NOTICE。
- 安全问题请私下报告，见 [SECURITY.md](SECURITY.md)。
- 欢迎提 issue，改动先开 issue 说明，见 [CONTRIBUTING.md](CONTRIBUTING.md)。
