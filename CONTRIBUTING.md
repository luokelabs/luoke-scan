# 参与贡献

螺壳扫描现在处于**封闭测试**。欢迎提 issue：

- **报错了、漏报了**：哪条发现（标题，结论是放心删 / 要确认 / 仅供参考）、你觉得应该是什么、为什么。**不要贴真实的文件列表、扫描结果或 `luoke-scan` 的整段输出**，路径换成编造的（比如 `~/Projects/demo-app`、`io.example.removed`）；能写成 `evals/cleanup/cases.json` 或 `evals/skills/cases.json` 那样的合成用例最好，我们会把它加进评测。
- **清理出了问题**：清了不该清的、放不回、要密码的那一步不对：写清楚是哪一类、做了什么、看到什么、期望什么；附截图前先遮住路径和文件名。
- **安全问题**不要开公开 issue，见 [SECURITY.md](SECURITY.md)。

## 改代码

1. **先开 issue 说明要改什么、为什么**，商量好再动手。加规则、改清理、改提示词、改给螺壳的接口（MCP 工具、outbox、配件清单 `packaging/luoke-accessory.json`）尤其要先说。
2. Go（版本见 `go.mod`），第三方包只有 Go 团队的 `golang.org/x/sys`，再加要先问；cgo 只在三处（FSEvents 变更日志、键盘监听、可用容量），别处不加。评测脚本只用 Python 标准库。代码注释用英文，文档、界面文字和提交信息用简体中文（代码标识、路径保留英文）。
3. 提交前跑：

   ```bash
   go vet ./...
   go test ./...
   go build -o .build/go/luoke-scan ./cmd/luoke-scan
   python3 -I bench/test_checks.py
   python3 -I blackbox/run.py
   ```

   （PATH 上的 `clang` 用不了时，命令前加 `CC=/usr/bin/clang`。）测试只用生成的假用户目录和假的扫描器（假 clamscan、freshclam、sigtool、yara 都是 shell 脚本），只在临时目录里读写，不碰你的家目录、不联网、不弹框，socket 只开在临时目录里的 Unix socket 上。自己试命令行也一样：用 `--fixture` 或 `--home <假目录> --data .dev/<名字>`，见 README「从源码构建和开发」；不要对自己的 Mac 跑会改动东西的命令。
   - 给螺壳 agent 的 MCP 和卡片另有一份自测 `scripts/agent_selftest.py`，要一份 luoke-agent 的代码，它现在还没公开，外部贡献者跑不了，由维护者在合并前跑。
   - agent 在几种处境下看到的答复（outbox、卡片、基础页、权限、点按的答复）录在 [fixtures/agent/](fixtures/agent/README.md) 里，是和 agent 之间的接口说明。`python3 scripts/record_agent_fixtures.py --check` 用 Go 版（`.build/go/luoke-scan`）重录一遍和它比：改了 agent 看到的东西就不过。是有意的改动就重录、一起提交，并在 PR 里说清 agent 那边要不要跟着改：

     ```bash
     go build -o .build/go/luoke-scan ./cmd/luoke-scan
     python3 scripts/record_agent_fixtures.py
     ```
   - `blackbox/` 是从外面测的一套：只通过命令行跑 `luoke-scan`，看输出和假目录里的文件怎么变，和 `blackbox/golden/` 里存的比（不看数据库和程序内部，换一种写法也能拿它对）。改了报出来的东西就不过；是有意的改动就 `python3 blackbox/run.py --record --only <场景>` 重录、一起提交，PR 里说清变了什么。见 [blackbox/README.md](blackbox/README.md)。
   - GitHub 上的检查（`.github/workflows/ci.yml`）不是每个 PR 都跑：PR 说明里勾上 `- [x] 跑 CI` 才跑（模板里有这一行），之后推新提交也跑。它在 GitHub 的 macOS 机器上跑 `go vet`、`go test`、下面第 4 条的三套评测和 `blackbox/run.py`，在 Linux 上跑 `bench/test_checks.py`；agent 自测、模型评测还是在本机跑。
4. **改规则要跑它的评测**：
   - 不用点就清的四类（会重建的缓存、装好了的应用的安装包、下载里的重复文件、测试工具留下的临时文件夹）：`.build/go/luoke-scan eval-cleanup`，**挑错必须是 0**。加一种新的（新的缓存位置、新的临时文件夹前缀），同时加上它「看着像、但不该清」的用例。见 [evals/cleanup/README.md](evals/cleanup/README.md)。
   - AI skill 的检查：`.build/go/luoke-scan eval-skills`，恶意的要全部报出，正常的一个都不能报成高。改了 `evals/skills/` 的用例或示范，跑 `.build/go/luoke-scan make-skill-evalset` 重新生成评测集和提示词示范，一起提交。见 [evals/skills/README.md](evals/skills/README.md)。
   - 给 AI 看的说明文件（AGENTS.md、CLAUDE.md、Cursor 的规则……）的检查：`.build/go/luoke-scan eval-agentfiles`，规矩同上，用例在 `evals/agentfiles/cases.json`。改了 skill 的检查也要跑它（两边用同一套文字检查）。
   - 报出来的东西更重了、更轻了，在 PR 里说清楚为什么，附上评测结果。
5. **改了 `prompts/` 或 `bench/evalsets/` 要重跑模型评测** `bench/run_eval.py`（要一个本机模型服务，用法见 README「评测」），硬性条目要全过。扫描发给模型的请求和评测程序发的逐字节一样，所以提示词改一个字都要重评；评测集里的数据都是合成的，不要放真实的路径和文件名。
6. **守住这几条**：
   - **规则判断，模型只讲**：是不是垃圾、能不能删、风险多高由规则决定；模型说的只附在发现下面，不改结论、轻重、标题。
   - **查的时候只读**：改动只来自用户点过的方案，和规则挑出的那四类；会改动东西的 MCP 调用没有用户点按就拒绝。
   - **删除一律移到废纸篓、记进清理记录、能放回**。例外只有删了不丢东西的两种：会重建的缓存（工具会自己重建）和失效的链接，直接删。不要加放不回的删除，也不要加「先删再说」的捷径。
   - **要密码的一步只做用户确认的那几项**：以管理员身份运行的是单独签名的 `luoke-scan-admin` 加方案编号，不是拼出来的命令字符串；它每一项重新判断，也移到废纸篓。
   - **内容不出本机**：文件内容、密码和密钥的值不进日志、记忆、outbox 和卡片；不加新的联网。
   - **不链接 libclamav**（也不链接 ClamAV、YARA 带的任何库）：ClamAV 是 GPLv2，螺壳扫描只把它当单独的程序起（`clamscan`、`freshclam`、`sigtool`），YARA 也一样，这是本项目能用 Apache-2.0 发布的前提。要用它们的新功能，也只能经命令行。
   - **不开 socket、不监听网络**：给螺壳 agent 的 MCP 只经螺壳本体起的 `luoke-scan mcp` 的标准输入输出，一个请求一个进程；要密码的那一步只经本体（`LUOKE_HOST_FD`），只交参数，不交命令。
7. **README 有中英两份**（`README.md`、`README.en.md`），改一份就在同一个提交里改另一份。

## 行为准则

友善、就事论事，尊重每一位参与者。
