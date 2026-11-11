// The usage text (blackbox/golden/cli/usage.json records it).

package main

const usage = "用法：\n" +
	"  luoke-scan scan --home <目录> --data <目录> [--tmp <目录>] [--projects <目录>]… [--tool-dir <目录>] [--json]\n" +
	"  luoke-scan scan --this-mac [--autoclean] [--projects <目录>]… [--json]   查这台 Mac（主控的空闲任务带 --autoclean 起）\n" +
	"  luoke-scan scan --fixture <假目录> [--json]     查假目录（外部测试 blackbox/ 用）\n" +
	"      [--clock <时间>] [--no-full-disk-access]   假目录的时钟停在这个 ISO 8601 时间；当作没有完全磁盘访问（录 fixtures/agent 用）\n" +
	"      [--update-first]                          还没有病毒库就先下载（--this-mac 一直这样）\n" +
	"  luoke-scan scan --this-mac --quick             两轮之间看一眼新下载的（下载、桌面有动静才扫，只扫病毒；用电池、低电量模式、内存紧张时不看）\n" +
	"  luoke-scan report [--data <目录>]              上一轮的结果，按放心删、要确认、仅供参考分开列\n" +
	"  luoke-scan findings --data <目录> [--json]     上一轮的发现，每条的全部细节\n" +
	"  luoke-scan status --data <目录> [--json]       上一轮什么时候查的、多少条、病毒库日期、哪些项没扫描\n" +
	"  luoke-scan update --data <目录> [--tool-dir <目录>] [--force]   更新病毒库（每天最多一次，--force 不管这条）\n" +
	"  luoke-scan malicious-import --data <目录> <路径>   从本机的 OSV 文件（JSON、文件夹或 .zip）导入已知恶意包的名单，只留 MAL- 开头的；加进原有的名单（同一编号的换新），不联网\n" +
	"  luoke-scan cleaned --this-mac [--json]         清理记录：移进废纸篓的、直接删的（缓存），哪些还能放回\n" +
	"  luoke-scan restore --this-mac <编号>…          放回：记录里的编号（c-…），或一次清理的整批（p-… / auto-…）；原位置有同名的就放在旁边\n" +
	"  luoke-scan system --this-mac                   上一轮查到的要密码才能删的：系统目录里的卸载残留、旧的 Intel 版 Homebrew\n" +
	"  luoke-scan system --this-mac --trash a0,a1     把这几项移到废纸篓：sudo 在这个终端里问密码，每次都问。不要加 sudo 跑本程序\n" +
	"  luoke-scan eval-cleanup [--cases <文件>] [--json]   清理规则评测（默认 evals/cleanup/cases.json）：挑错一个就退出码 1；--json 逐条的结果\n" +
	"  luoke-scan eval-skills [--cases <文件>]        skill 静态检查评测（默认 evals/skills/cases.json）：漏报恶意的、正常的报成高的，退出码 1\n" +
	"  luoke-scan eval-agentfiles [--cases <文件>]    给 AI 看的说明文件检查评测（默认 evals/agentfiles/cases.json）：同上\n" +
	"  luoke-scan make-skill-evalset                 用扫描拼输入的代码生成 skill 语义检查的评测集和提示词示范（bench/evalsets/skills.json、prompts/skills.examples.json）\n" +
	"  luoke-scan mcp --this-mac                      给 agent 的 MCP：标准输入一条 JSON-RPC（或一行一条），标准输出答复\n" +
	"  luoke-scan version\n" +
	"\n" +
	"给 agent 的 MCP 由螺壳本体每个请求起一次 luoke-scan mcp --this-mac，经它的标准输入输出说话；要密码的那一步经本体弹框\n" +
	"（LUOKE_HOST_FD）。完全磁盘访问授给螺壳本身，由螺壳起的 luoke-scan 跟着它用；luoke-scan 从不开 socket。\n" +
	"\n" +
	"查的时候只读。唯一的例外是带 --autoclean（主控的空闲任务这样起）：查完把不用点就清的四类清掉（会重建的缓存直接删；\n" +
	"装好了的应用的安装包、下载文件夹里的重复文件、测试工具留下的临时文件夹移进废纸篓，能放回），每次都报给你。默认关：\n" +
	"你在卡片或设置里点了「以后自动清」才清。--autoclean 只和 --this-mac、--fixture 一起用；agent 叫的那一轮（--for-agent）不清。一个数据目录同时只跑一轮。\n" +
	"开发和测试时 --home 指向假目录（外部测试造的，见 blackbox/README.md），--data 指向 .dev/ 下的目录。\n" +
	"--this-mac：家目录、本用户的临时目录、常见的项目目录（~/Developer、~/Projects、~/Documents/GitHub、~/code、~/src、\n" +
	"~/repos、~/workspace 里有的），数据放在 ~/.luoke-scan；findings、status、update、malicious-import 也认它（只换数据目录）。\n" +
	"report 不给 --data 就看这台 Mac 的（~/.luoke-scan）。\n"
