# 安全问题

螺壳扫描会读这台 Mac 上的大部分东西，还能把文件移到废纸篓、经你输入密码删系统目录里的残留，所以安全问题我们优先处理。下面这些都算：

- **东西离开本机**：扫描结果、文件内容、找到的密码和密钥（哪怕只是位置）被发出去；或者扫描除了更新病毒库以外还连了别的地方。
- **清理越界**：动了你没确认的东西（规则挑出、不用点就清的那四类以外的），动了别的账户的东西，或者清掉的东西放不回（会重建的缓存和失效的链接是直接删的，这两种除外）。
- **要密码的那一步做多了**：以管理员身份运行的 `luoke-scan-admin` 做了你确认的那几项以外的事，或者别的程序能借它、借 macOS 的密码框以管理员身份运行别的东西。
- **接口被别人用**：别的账户、别的程序或网页能连上给螺壳 agent 用的 socket（`~/.luoke-scan/run/agent.sock`），或者不经你点按就能让它执行清理方案、改设置。
- **被扫描的内容反过来指挥程序**：文件名、文件内容、AI skill、配置文件里的文字能让程序执行命令、连一个地址、改变结论，或者让本机模型的话超出一段说明（比如替某个东西担保、教你运行命令）。

**请不要在公开 issue 里写细节**，用 GitHub 的私密漏洞报告：

1. 打开本仓库的 **Security** 页；
2. 点 **Report a vulnerability**，写清楚版本（`luoke-scan version`，或 `packaging/luoke-accessory.json` 的 `version`）、macOS 版本、怎么复现、可能的影响。

如果本仓库的 Security 页还没有这个按钮，请报到顶层仓库 [luokelabs/luoke](https://github.com/luokelabs/luoke/security)。我们会尽快回复，修好以后在发布说明里注明。

请不要在报告里附上真实的文件列表、路径、扫描结果（`~/.luoke-scan` 里的任何文件）、密码或密钥。需要样本时，用 `luoke-scan fixture` 生成的假用户目录，或者照 `evals/` 里的合成用例写一个；路径用编造的。

---

**English.** Please report security issues privately via **Security → Report a vulnerability** on this repository (or on [luokelabs/luoke](https://github.com/luokelabs/luoke/security) if the button is not there yet), not in public issues. In scope: findings, file contents or the location of secrets leaving the Mac, or any connection besides the virus-database update; a clean-up touching something you did not confirm (beyond the four kinds the rules clean on their own), another account's files, or anything that cannot be put back (rebuildable caches and dead links, which are deleted outright, excepted); the administrator step (`luoke-scan-admin`) doing more than the items you confirmed, or being usable to run anything else as root; other accounts, programs or web pages reaching the agent socket, or a plan being carried out without your click; scanned files, skills or configuration steering the program, or steering the local model beyond an explanation. Please don't include real file lists, paths, scan results or secrets; use a synthetic home from `luoke-scan fixture` or a made-up case like those in `evals/`.
