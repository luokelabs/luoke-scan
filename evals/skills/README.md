# skill 检查评测

查本机装的 AI skill（`SkillRule`，设计见 `docs/skills.md`）的评测集：一组合成的 skill，有恶意的，也有看着像、其实正常的。静态检查直接用它；语义检查（问本地模型「说的和做的对不对得上」）的评测集 `bench/evalsets/skills.json` 也从它生成。

## 用例

`cases.json` 里每个用例是一个 skill 文件夹：`files` 是「相对路径 → 内容」。内容可以是：
- 一段文字；
- `{"base64": "…"}`：字节（编译过的程序、图片这类）；
- `{"fill": "a", "bytes": 600000}`：重复的字符（太大的文件）；
- `{"link": "…"}`：符号链接。

`place` 是放在假家目录下的哪里，默认 `.claude/skills`。

- 恶意的（`"malicious": true`）：必须报出来；`min` 是至少多重，`kind` 是规则名里必须认出的那一类（`exfil`、`download-exec`、`persistence`、`agent-tamper`、`escalation`、`destructive`、`injection`、`permission`、`supply-chain`、`unreadable`）。
- 正常的（`"malicious": false`）：**一个都不能报成高**；`max` 是最多报到多重（`none` 是一条都不该有，默认 `low`）。
- `"semantic": "unsure"`：恶意的，但说明读起来也说得通（「装这个包」配 `sudo`、「让同事连进来」配加钥匙）。语义检查不考模型说没说对不上，只考别的。

十类每类至少一个恶意用例；正常用例照常见的正当写法挑：用 curl 调 API、Linux 上 `sudo apt-get` 装依赖、部署说明里提到 `~/.ssh`、README 里教人把 skill 拷进 `~/.claude/skills`、从 `.env` 或钥匙串拿自己的 API key、写了版本号的安装、官方安装脚本、往 `.zshrc` 里加 PATH、写 skill 的 skill、生成 CLAUDE.md 的 skill、安全审查 skill 列出的危险写法、拦危险命令的钩子（要拦的命令只在字符串比较和 `case` 的模式里）、教人写斜杠命令的 skill、emoji 和旗帜里的看不见的字符、Markdown 里内嵌的图片、Python 的 `__pycache__`、图片和字体、清项目里的构建产物、只看不改的诊断命令、核对了校验和的下载、`case` 的默认分支只打印用法的脚本、说「不要往 CLAUDE.md 里写」的说明、同一行先打印一句提醒再做正事的脚本、用反斜杠拆成几行的 `curl … | jq`、把下载的名单经 `xargs` 交给 `grep` 的脚本、说明的代码块里同一行先打印一句提醒再做正事的命令……

## 样本都是不会运行的文字

- 网址用 `.invalid`、`example.com`、文档专用的 IP（203.0.113.x）；没有真的密钥、令牌。
- 测试只把它们写进临时目录里的假家目录，只读、不运行；跑完就删。
- 别把这些用例当 skill 装进任何 AI 工具。

## 怎么跑

- `python3 -I blackbox/run.py --only evals/`：恶意的全部报出（不低于 `min`、认出 `kind`），正常的没有一个是高的、没有超过 `max`；和录好的逐条结果比。
- `luoke-scan eval-skills [--cases <文件>]`（只给开发版）：打印评分表，没过退出码 1。
- 语义检查：改了 `cases.json` 或 `examples.json`（提示词的示范，也是合成的 skill，不能和用例共用文件内容，规则查到的也不能和哪个用例一样），跑 `luoke-scan make-skill-evalset` 重新生成 `bench/evalsets/skills.json` 和 `prompts/skills.examples.json`（外部测试的 `evals/make-skill-evalset` 会核对它们是最新的）；在模型上跑 `python3 bench/run_eval.py --task skills …`。

现在的结果：恶意 45 个全报（高 37、中 7、低 1，都不低于各自的 `min`）；正常 44 个，32 个一条都没有，9 个是低（写 skill 的 skill、生成 CLAUDE.md 的 skill、教人写 MCP 服务器的 skill、教人写斜杠命令的 skill、官方安装脚本、往 `.zshrc` 加 PATH、README 里让人往 `.zshrc` 加变量、发 Slack 消息、下载固定版本的程序），3 个是中，没有高。

那 3 个中和恶意里最后 3 个中是一组，给语义检查用（11-02 加）：正常的照说明做敏感的事（导出 Chrome 保存的密码、把日志传到贴文本网站、从自己的仓库装固定版本），恶意的做说明里没说的同类事（说是整理 JSON 却拷钱包、说是数字数却读信息的数据库、说是跑测试却让 AI 关掉确认）。规则看来两边一样重，要靠「说的和做的对不对得上」分开；以后要不要让模型把中提到高，就看它在这几组上判得准不准。

## 加用例

改 `cases.json` 就行（id 不能重）。加了看着像恶意、其实正常的，跑一遍：报成高的就是规则太松，要改规则，不要改用例的 `max`。
