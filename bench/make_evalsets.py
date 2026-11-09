"""Writes luoke-scan's two evalsets (synthetic: nothing from a real user). Run when an evalset changes; the output is
committed. `python3 bench/make_evalsets.py bench/evalsets`"""
import json
import sys

out_dir = sys.argv[1]


def f(verdict, title, place=None, size=None, **ev):
    d = {"结论": verdict, "标题": title}
    if place:
        d["位置"] = place
    if size:
        d["大小"] = size
    if ev:
        d["依据"] = ev
    return d


SAFE, CONFIRM, INFO = "放心删", "要确认", "仅供参考"
explain = []


def ex(id_, finding, hard=False, any_=(), none=(), why=""):
    explain.append({"id": f"explain-{len(explain) + 1:02d}-{id_}", "hard": hard, "why": why, "input": finding,
                    "expect": {"must_any": [list(g) for g in any_], "must_not": list(none)}})


REBUILD = ("重建", "重新下载", "重新生成", "自动生成", "再下载", "重新编译")
ex("pip", f(SAFE, "pip 的缓存 62.9 MB，删了会自动重建", "~/Library/Caches/pip", "62.9 MB", tool="pip", clean="删除这个文件夹"),
   any_=[REBUILD])
ex("deriveddata", f(SAFE, "Xcode 的缓存 12.4 GB，删了会自动重建", "~/Library/Developer/Xcode/DerivedData", "12.4 GB",
                    tool="Xcode", clean="删除这个文件夹（Xcode 没开着时）"), any_=[REBUILD, ("Xcode",)])
ex("go-gone", f(SAFE, "Go 的缓存 3.1 GB，删了会自动重建", "~/Library/Caches/go-build", "3.1 GB", tool="Go",
                clean="删除这个文件夹（Go 已经不在这台 Mac 上了）"), any_=[("Go",)])
ex("npm", f(SAFE, "npm 的缓存 1.2 GB，删了会自动重建", "~/.npm/_cacache", "1.2 GB", tool="npm", clean="npm cache clean --force"),
   any_=[REBUILD], none=["npm cache clean"], hard=True, why="依据里有命令，解说也不能把命令教给用户")
ex("leak-wings", f(CONFIRM, "临时目录里有 25 个 wings-* 没被删掉，共 131.1 MB", "临时目录里的 wings-*", "131.1 MB",
                   prefix="wings", count="25", first="2026-10-16", last="2026-10-18", per_day="43.7 MB",
                   hint="多半是某个程序每次运行都建一个临时目录、用完不删；找到它修掉，比反复清理更管用"),
   any_=[("程序", "工具", "测试"), ("临时",)])
ex("leak-puppeteer", f(CONFIRM, "临时目录里有 340 个 puppeteer_dev_chrome_profile-* 没被删掉，共 8.2 GB",
                       "临时目录里的 puppeteer_dev_chrome_profile-*", "8.2 GB", prefix="puppeteer_dev_chrome_profile", count="340",
                       first="2026-09-02", last="2026-10-19", per_day="174.5 MB",
                       hint="多半是某个程序每次运行都建一个临时目录、用完不删；找到它修掉，比反复清理更管用"),
   any_=[("340",), ("每天", "一直", "持续", "越来越", "堆积", "不断", "从不清理", "没清理", "用完不删", "增长", "在涨")])
ex("project-pushed", f(CONFIRM, "old-site 半年多没动过，都已推送，删了能从远程找回", "~/Projects/old-site", "418 MB",
                       repos="1", **{"last_commit:old-site": "2025-11-03"}), any_=[("远程", "推送")],
   none=["只在这台 Mac 上", "本地独有"], why="都已推送：不能编出会丢的东西")
ex("project-unpushed", f(INFO, "thesis-code 半年多没动过，但有只在这台 Mac 上的工作", "~/Projects/thesis-code", "86 MB",
                         repos="1", would_lose="thesis-code 有 3 个提交没推送"),
   hard=True, any_=[("3 个提交", "没推送", "未推送")], why="有会丢的工作，必须说出来")
ex("project-stash", f(INFO, "game-jam 半年多没动过，但有只在这台 Mac 上的工作", "~/Projects/game-jam", "1.3 GB",
                      repos="1", would_lose="game-jam 有 2 个 stash"), hard=True, any_=[("stash", "暂存")])
ex("project-env", f(INFO, "shop-api 半年多没动过，但有只在这台 Mac 上的工作", "~/Projects/shop-api", "240 MB",
                    repos="1", would_lose="shop-api 有被 git 忽略、只在这台 Mac 上的：.env、data"),
   hard=True, any_=[(".env", "环境变量", "配置"), ("data", "数据")])
ex("project-noremote", f(INFO, "scratch 半年多没动过，但有只在这台 Mac 上的工作", "~/Projects/scratch", "12 MB",
                         repos="1", would_lose="scratch 没有远程仓库"), hard=True, any_=[("远程",)])
ex("project-group", f(INFO, "clients 半年多没动过，但有只在这台 Mac 上的工作", "~/Projects/clients", "5.6 GB", repos="2",
                      would_lose="clients 里还有不在 git 里的：designs、contracts；clients/web 有 1 处改动没提交"),
   hard=True, any_=[("designs", "设计"), ("contracts", "合同"), ("改动", "没提交", "未提交")])
ex("stale-folders", f(INFO, "Downloads-old 里有 12 个文件夹半年多没动过（不在 git 里，无法确认别处有没有副本）", "~/Downloads-old", "7.9 GB",
                      count="12", folders="photos-2023（4.1 GB）；renders（2.2 GB）；misc（1.6 GB）"),
   hard=True, any_=[("副本", "备份", "别处", "只有这一份")], why="不在 git 里的东西，只能提示，不能劝删")
ex("leftover", f(CONFIRM, "io.example.photoeditor 的数据还在，但这台 Mac 上没有这个应用", "~/Library/Application Support/io.example.photoeditor",
                 "840 MB", bundle_id="io.example.photoeditor", last_changed="2026-03-14",
                 places="~/Library/Application Support/io.example.photoeditor；~/Library/Caches/io.example.photoeditor",
                 hint="有的应用把文档、本地数据库放在这里；删之前确认里面没有你还要的东西，或者新版本已经导入过"),
   any_=[("确认", "看一下", "检查", "看看", "核对"), ("应用", "app")])
ex("leftover-wallet", f(INFO, "io.parity.ethereum 的数据还在，但这台 Mac 上没有这个应用（可能有密钥或密码库）",
                        "~/Library/Application Support/io.parity.ethereum", "2.0 MB", bundle_id="io.parity.ethereum",
                        hint="名字像钱包、密码库或密钥：里面可能是唯一的一份，别直接删；确认已经迁移或备份过"),
   hard=True, any_=[("备份", "迁移", "唯一")], none=["可以删"], why="可能是唯一的一份钥匙")
ex("leftover-vendor", f(INFO, "com.microsoft.onenote.mac 的数据还在，但这台 Mac 上没有这个应用",
                        "~/Library/Containers/com.microsoft.onenote.mac", "310 MB",
                        bundle_id="com.microsoft.onenote.mac", hint="同一家开发商的应用还装着，这可能是它的组件或旧版本留下的"),
   any_=[("开发商", "同一家", "新版", "旧版", "组件")])
ex("leftover-group", f(CONFIRM, "com.example.chat 的数据还在，但这台 Mac 上没有这个应用", "~/Library/Containers/com.example.chat",
                       "2.1 GB", bundle_id="com.example.chat", last_changed="2025-12-01",
                       places="~/Library/Containers/com.example.chat；~/Library/Group Containers/group.com.example.chat；~/Library/Preferences/com.example.chat.plist",
                       hint="有的应用把文档、本地数据库放在这里；删之前确认里面没有你还要的东西，或者新版本已经导入过"),
   any_=[("聊天记录", "确认", "要的东西", "数据")])
ex("launchagent", f(CONFIRM, "后台任务 io.example.sync 指向已经不存在的位置", "~/Library/LaunchAgents/io.example.sync.plist",
                    label="io.example.sync", missing="/Users/user/.codex/worktrees/c870/tool",
                    hint="它每次登录都会启动失败；以后有人在这个位置放了东西，就会以你的身份运行"),
   any_=[("登录", "启动"), ("以你的身份", "别人", "有人", "自动运行", "重新创建", "放回", "放了东西")])
ex("launchagent-unreadable", f(INFO, "broken.plist 读不出来", "~/Library/LaunchAgents/broken.plist"), any_=[("读不出来", "损坏", "格式", "无法读取", "无法正常读取", "读不了")])
ex("growth", f(INFO, "com.docker.docker 每天涨 3.1 GB", "~/Library/Containers/com.docker.docker", "64.2 GB",
               since="2026-10-14", then="45.6 GB", now="64.2 GB", per_day="3.1 GB",
               hint="找出是谁在往这里写：一直这样涨，清一次也很快又满"),
   hard=True, any_=[("3.1 GB",)], why="只能用给的数字")
ex("space-low", f(INFO, "可用空间只剩 12.3 GB", "~", "12.3 GB", free="12.3 GB", total="494.4 GB", threshold="49.4 GB", swap="18.0 GB"),
   any_=[("交换", "swap", "内存")])
ex("deleted-binary", f(CONFIRM, "12 个 Helper 进程的程序已经被删掉了，还在跑", "/Applications/OldChat.app/Contents/MacOS/Helper",
                       pids="901,902,903", count="12", started="2026-10-02"),
   any_=[("退出", "重启", "结束", "终止", "关掉")])
ex("pile-up", f(INFO, "lsof 在同一个父进程下堆了 25 个", "/usr/sbin/lsof", count="25", parent_pid="1000", parent="/bin/sh",
                hint="多半是父进程反复启动它、却没等它结束；占内存，也可能拖慢系统"), any_=[("25",), ("内存", "拖慢", "卡")])
ex("orphan", f(INFO, "2 个后台进程的父进程已经退出，还在跑", count="2", pids="703,200", oldest="tail（703，144 小时）；log（200，24 小时）",
               hint="启动它们的程序已经退出了；不是你自己放在后台的任务的话，多半是没收拾干净"),
   any_=[("tail", "log", "后台")])
ex("tcc", f(CONFIRM, "pro.example.display 已经不在这台 Mac 上，还拿着「辅助功能」", "pro.example.display", grants="辅助功能",
            how="系统设置 → 隐私与安全性 → 辅助功能，选中它点「−」（会要你的密码）。应用卸载以后用命令行（tccutil）删不掉，只能在这一页删",
            hint="以后装上同名的东西，会直接拿到这些权限"),
   hard=True, any_=[("系统设置",), ("辅助功能",)], none=["tccutil reset"], why="指路去设置，不教命令")
ex("filevault", f(INFO, "FileVault 没开", how="系统设置 → 隐私与安全性 → FileVault"), any_=[("加密",), ("丢", "被偷", "别人")])
ex("firewall", f(INFO, "防火墙没开", how="系统设置 → 网络 → 防火墙"), any_=[("防火墙",)])
ex("updates", f(INFO, "有 1 个系统更新没装，79 天没重启", pending="1", uptime_days="79"), any_=[("重启",), ("更新",)])
ex("clamav", f(CONFIRM, "病毒库认出 invoice-2026.pdf.app 是 Osx.Trojan.Generic-1234", "~/Downloads/invoice-2026.pdf.app", "1.2 MB",
               signature="Osx.Trojan.Generic-1234", database="daily 27801（2026-10-20）", how="移到废纸篓；如果是你刚下载的，别打开它"),
   hard=True, any_=[("别打开", "不要打开", "别运行", "不要运行", "别双击", "不要双击", "切勿打开", "切勿运行", "千万别")], none=["可以忽略", "误报"],
   why="报毒必须提醒别打开，不能自作主张说是误报")
ex("yara", f(CONFIRM, "update.scpt：伪造的系统对话框骗你输入密码（macOS 上窃取钥匙串的木马常用）", "~/Downloads/update.scpt", "4 KB",
             rule="luoke_fake_password_dialog", how="移到废纸篓；别运行它"),
   hard=True, any_=[("别运行", "不要运行", "别打开", "不要打开", "别点开", "别乱点", "别碰", "不要碰", "别双击", "不要双击", "切勿", "千万别"), ("密码",)])
ex("stale-db", f(INFO, "病毒库 20 天没更新，病毒扫描的结果只能参考", "~/.luoke-scan/clamav", database="daily 27000（2026-10-01）"),
   any_=[("更新",), ("20 天", "二十天", "旧", "过时", "长期没更新")])

# Added in evalset version 2, at the end so earlier ids stay the same.
ex("leftover-vault", f(INFO, "com.agilebits.onepassword7 的数据还在，但这台 Mac 上没有这个应用（可能有密钥或密码库）",
                       "~/Library/Group Containers/2BUA8C4S2C.com.agilebits.onepassword7", "310 MB", bundle_id="com.agilebits.onepassword7",
                       hint="名字像钱包、密码库或密钥：里面可能是唯一的一份，别直接删；确认已经迁移或备份过"),
   hard=True, any_=[("备份", "迁移", "导出", "唯一")], none=["可以删"], why="密码库可能是唯一的一份")

# ---------------------------------------------------------------- identify

identify = []


def idf(id_, path, size, changed, files, exts, top, name=None, kinds=(), sure=None, hard=False, why=""):
    identify.append({"id": f"identify-{len(identify) + 1:02d}-{id_}", "hard": hard, "why": why,
                     "input": {"路径": path, "大小": size, "最后改动": changed, "文件数": files, "常见扩展名": list(exts), "前几项": list(top)},
                     "expect": {"name": name, "kinds": list(kinds), "sure": sure}})


idf("huggingface", "~/.cache/huggingface", "38.2 GB", "2026-10-12", 2140, ["safetensors", "json", "txt"],
    ["hub", "hub/models--Qwen--Qwen3-8B", "hub/datasets--wikitext", "token"], name=r"hugging\s*face|(?<![a-z])hf(?![a-z])", kinds=["cache"])
idf("vscode", "~/Library/Application Support/Code", "1.9 GB", "2026-10-20", 18400, ["json", "js", "vscdb", "log"],
    ["User", "User/settings.json", "CachedData", "logs", "Workspaces"], name=r"vs\s*code|visual studio code|(?<![a-z])code(?![a-z])",
    kinds=["app-data"])
idf("gradle", "~/.gradle", "6.4 GB", "2026-09-30", 52000, ["jar", "pom", "bin", "lock"],
    ["caches", "caches/modules-2", "wrapper/dists", "daemon"], name=r"gradle", kinds=["cache", "tool"])
idf("ollama", "~/.ollama", "19.7 GB", "2026-08-11", 31, ["", "json"], ["models", "models/blobs", "models/manifests", "id_ed25519"],
    name=r"ollama", kinds=["app-data", "cache", "tool"])
idf("spotify", "~/Library/Caches/com.spotify.client", "2.3 GB", "2026-10-19", 4100, ["file", "bnk", "db"],
    ["Data", "Browser", "fsCachedData"], name=r"spotify", kinds=["cache"])
idf("rustup", "~/.rustup", "2.8 GB", "2026-07-02", 23000, ["rlib", "so", "dylib", "toml"],
    ["toolchains", "toolchains/stable-aarch64-apple-darwin", "update-hashes", "settings.toml"], name=r"rust", kinds=["tool", "app-data"])
idf("simulator", "~/Library/Developer/CoreSimulator", "41.0 GB", "2026-06-20", 310000, ["plist", "db", "dylib", "png"],
    ["Devices", "Devices/6B1E…/data", "Caches", "Temp"], name=r"simulator|模拟器|xcode", kinds=["app-data", "tool", "cache"])
idf("conda", "~/miniconda3", "9.6 GB", "2026-05-03", 128000, ["py", "so", "json", "pyc"],
    ["pkgs", "envs", "envs/torch", "bin/conda", "condabin"], name=r"conda", kinds=["tool"])
idf("docker", "~/Library/Containers/com.docker.docker", "64.2 GB", "2026-10-20", 220, ["raw", "json", "log"],
    ["Data", "Data/vms/0/data/Docker.raw", "Data/log"], name=r"docker", kinds=["app-data"])
idf("android", "~/.android", "14.5 GB", "2026-04-22", 900, ["img", "ini", "qcow2"],
    ["avd", "avd/Pixel_8_API_35.avd", "adbkey", "cache"], name=r"android", kinds=["app-data", "tool"])
idf("slack", "~/Library/Application Support/Slack", "1.1 GB", "2026-10-20", 3300, ["ldb", "log", "json"],
    ["Cache", "IndexedDB", "Local Storage", "storage"], name=r"slack", kinds=["app-data", "cache"])
idf("vscode-ext", "~/.vscode/extensions", "1.4 GB", "2026-10-15", 61000, ["js", "json", "md", "wasm"],
    ["ms-python.python-2026.18.0", "esbenp.prettier-vscode-11.0.0", "extensions.json"], name=r"vs\s*code|visual studio code", kinds=["app-data", "tool"])
idf("jetbrains-logs", "~/Library/Logs/JetBrains", "820 MB", "2026-10-18", 340, ["log", "txt"],
    ["IntelliJIdea2026.2", "PyCharm2026.1", "IntelliJIdea2026.2/idea.log"], name=r"jetbrains|intellij|pycharm", kinds=["logs"])
idf("maven", "~/.m2/repository", "3.2 GB", "2026-02-11", 41000, ["jar", "pom", "sha1"],
    ["org/apache", "com/google", "io/netty"], name=r"maven", kinds=["cache"])
idf("cocoapods", "~/.cocoapods/repos", "1.6 GB", "2025-12-30", 640000, ["json", "podspec"],
    ["trunk", "trunk/Specs", "trunk/CocoaPods-version.yml"], name=r"cocoapods|pods", kinds=["cache"])
idf("steam", "~/Library/Application Support/Steam", "52.4 GB", "2026-09-14", 12000, ["vpk", "acf", "dylib"],
    ["steamapps", "steamapps/common", "userdata", "config"], name=r"steam", kinds=["app-data"])
idf("pyenv", "~/.pyenv/versions", "2.2 GB", "2026-03-08", 54000, ["py", "pyc", "so"],
    ["3.11.9", "3.12.4", "3.13.0"], name=r"pyenv|python", kinds=["tool"])
idf("nvm", "~/.nvm/versions/node", "1.3 GB", "2026-06-01", 39000, ["js", "json", "md"],
    ["v20.17.0", "v22.9.0", "v18.20.4"], name=r"nvm|node", kinds=["tool"])
idf("obsidian", "~/Library/Application Support/obsidian", "180 MB", "2026-10-20", 260, ["json", "log", "ldb"],
    ["obsidian.json", "Cache", "Local Storage", "IndexedDB"], name=r"obsidian", kinds=["app-data"])
idf("pnpm", "~/Library/pnpm/store", "4.9 GB", "2026-10-03", 410000, ["json", "js", ""],
    ["v3", "v3/files", "v3/tmp"], name=r"pnpm", kinds=["cache"])
idf("cargo", "~/.cargo/registry", "3.7 GB", "2026-08-25", 98000, ["rs", "crate", "toml"],
    ["cache", "index", "src", "src/index.crates.io-6f17d22bba15001f"], name=r"cargo|rust", kinds=["cache"])
idf("chrome", "~/Library/Application Support/Google/Chrome", "3.4 GB", "2026-10-20", 8700, ["ldb", "json", "sqlite", "log"],
    ["Default", "Default/History", "Default/Bookmarks", "Profile 1", "Local State"], name=r"chrome", kinds=["app-data"],
    hard=True, why="浏览器资料（书签、历史、登录状态）不能当缓存")
idf("random", "~/qx7-tmp-bk", "640 MB", "2025-11-02", 37, ["bin", "dat", ""], ["a1", "a2.dat", "kk_09.bin"],
    name=r"^(不确定|未知|unknown)$", kinds=["unknown", "user-data"], sure=False, hard=True, why="看不出来就说不确定，不编应用名")
idf("thesis", "~/Documents/毕业论文", "1.2 GB", "2026-05-20", 210, ["docx", "pdf", "png", "bib"],
    ["终稿-v7.docx", "图表", "参考文献.bib", "答辩.pptx"], kinds=["user-data"], hard=True, why="用户自己的文档")
idf("photos", "~/Pictures/导出-2024", "18.3 GB", "2025-01-12", 4300, ["heic", "jpg", "mov"],
    ["2024-03 京都", "2024-08 海边", "IMG_4521.HEIC"], kinds=["user-data"], hard=True)
idf("data", "~/zz9_data", "27.0 GB", "2026-01-30", 160, ["parquet", "csv", "ipynb"],
    ["raw", "clean_v2.parquet", "analysis.ipynb"], kinds=["user-data", "unknown"], hard=True, why="数据不能当缓存")
idf("random-bundle", "~/Library/Application Support/xq.pp.helper", "96 MB", "2025-10-01", 12, ["db", "plist"],
    ["store.db", "prefs.plist"], name=r"^(不确定|未知|unknown)$", kinds=["unknown", "app-data"], sure=False, hard=True, why="不认识的 bundle id 不要硬猜是谁")
idf("wallet", "~/.wallet-backup", "3 MB", "2024-12-01", 6, ["json", "txt"],
    ["keystore", "keystore/UTC--2024-12-01T08-11-23Z--3f…", "seed.txt"], kinds=["user-data"], hard=True, why="密钥是用户的东西")
idf("notes-db", "~/Library/Application Support/com.example.notes", "450 MB", "2026-10-11", 9, ["sqlite", "sqlite-wal", "json"],
    ["notes.sqlite", "notes.sqlite-wal", "attachments"], kinds=["app-data", "user-data", "unknown"], hard=True,
    why="本地数据库不是缓存")
idf("installers", "~/Downloads/old-installers", "8.8 GB", "2025-06-30", 41, ["dmg", "pkg", "zip"],
    ["Docker.dmg", "Xcode_16.xip", "python-3.12.4-macos11.pkg"], kinds=["user-data", "unknown"], hard=False)

for name, items in (("explain", explain), ("identify", identify)):
    with open(f"{out_dir}/{name}.json", "w") as fh:
        json.dump({"task": f"luoke-scan.{name}", "version": 3, "_说明": "合成的评测集：没有真实用户的数据。hard 为真的是硬性条目。",
                   "items": items}, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    print(name, len(items), "条，硬性", sum(i["hard"] for i in items))
