#!/usr/bin/env python3
"""Whether the eval's own checks are right: good answers pass, bad ones do not. `python3 bench/test_checks.py`; no model."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_eval as r  # noqa: E402

ROOT = os.path.dirname(HERE)
P = r.load_prompt("explain")
PI = r.load_prompt("identify")
E = {i["id"].split("-", 2)[2]: i for i in json.load(open(os.path.join(HERE, "evalsets", "explain.json")))["items"]}
I = {i["id"].split("-", 2)[2]: i for i in json.load(open(os.path.join(HERE, "evalsets", "identify.json")))["items"]}
PS = r.load_prompt("skills")
SKILLS_RAW = open(os.path.join(HERE, "evalsets", "skills.json"), encoding="utf-8").read()
S = {i["id"].split("-", 2)[2]: i for i in json.loads(SKILLS_RAW)["items"]}

EXPLAIN = [
    ("yara", "Downloads 里有个 update.scpt，是伪装系统弹窗的木马，专骗你输密码。千万别双击运行，否则账号会被盗。", True),
    ("clamav", "这个文件被认出是木马，切勿运行，这不是误报。", True),
    ("clamav", "这可能是误报，可以忽略。", False),
    ("leftover-wallet", "里面可能是唯一的钥匙，不可以删，先确认备份或迁移过。", True),
    ("leftover-wallet", "这是以太坊钱包留下的数据，直接删风险不大。", False),
    ("stale-db", "病毒库 20 天没更新了，不用的话删掉也没事。", False),
    ("leftover", "确认没有要的东西后删掉即可，这是已卸载应用留下的数据。", True),
    ("project-unpushed", "thesis-code 有 3 个提交没推送，千万别直接删。", True),
    ("project-unpushed", "这个项目有 3 个提交没推送，直接删除会丢这些提交。", True),
    ("growth", "Docker 每天涨 3.1 GB，已经涨了 6 天。", False),
    ("growth", "Docker 从 45.6 GB 涨到 64.2 GB，每天 3.1GB，去年 2025 年就开始了。", False),
    ("growth", "Docker 的数据从 45.6 GB 涨到 64.2 GB，每天多 3.1 GB，找出是谁在写。", True),
    ("deriveddata", "这是 go 1.22 的编译缓存，Xcode 会自动重建。", True),
    ("npm", "npm 的缓存会重建，可以用rm -rf 删。", False),
    ("npm", "npm 的缓存，删了会自动重建。可以用 `npm cache clean --force`。", False),
    ("tcc", "去系统设置的辅助功能里删掉它，或者执行：tccutil reset All x。", False),
    ("tcc", "这个已卸载的应用还拿着辅助功能权限，去系统设置 → 隐私与安全性 → 辅助功能里删掉它。", True),
    ("project-group", "clients 里有设计稿和合同不在 git 里，删了会丢。", False),
    ("project-group", "clients 里有设计稿和合同不在 git 里，web 还有改动没提交，删了会丢。", True),
    ("clamav", "病毒库认出它是木马，别打开，文件已移到废纸篓。", False),
    # code review 2026-10-23
    ("stale-folders", "这 12 个文件夹别处可能没有副本，没什么风险，可以删掉腾出 7.9 GB。", False),
    ("project-env", "shop-api 里的 .env 和 data 只在这台 Mac 上，问题不大，删了不影响。", False),
    ("leftover-wallet", "这是以太坊钱包的数据，确认备份过以后，删掉它不会有影响。", False),
    ("project-unpushed", "thesis-code 有 3 个提交没推送，先运行 git push 推上去。", False),
    ("updates", "有 1 个系统更新没装，运行 softwareupdate -ia，再重启。", False),
    ("deleted-binary", "12 个 Helper 进程的程序已经被删掉了，用 kill 901 结束它们。", False),
    ("growth", "Docker 每天涨 3.1 GB，这 14 天一直在涨。", False),
    ("launchagent", "io.example.sync 已经 870 天启动失败，以后有人放了东西就会以你的身份运行。", False),
    ("leftover-wallet", "以太坊钱包应用已经删除了，但它的数据还在，里面可能是唯一的钥匙，先确认备份或迁移过。", True),
    ("deleted-binary", "Helper 的程序文件已删除，但还有 12 个进程在跑，退出或重启 OldChat 就好。", True),
    ("clamav", "病毒库认出它是木马，这不太可能是误报，别打开它。", True),
    ("stale-folders", "结论是仅供参考，不是「放心删」：这 12 个文件夹别处可能没有副本。", True),
    ("pip", "pip 的缓存，删了会自动重建。" + "这些是下载过的安装包" * 12, False),
    ("leftover-vault", "1Password 的数据还在，可能是唯一的一份密码库，先确认已经导出或迁移过。", True),
    ("leftover-vault", "这是 1Password 的旧数据，可以删掉腾出 310 MB。", False),
    ("project-pushed", "old-site 从 2025 年 11 月就没再改过，都已推送到远程，删了能找回。", True),
    ("leak-puppeteer", "从 9 月 2 日到 10 月 19 日，临时目录里一直在堆 340 个这样的文件夹，多半是某个程序用完不删。", True),
    ("leak-puppeteer", "从 9 月 3 日起，临时目录里一直在堆 340 个这样的文件夹，多半是某个程序用完不删。", False),
    ("project-env", "shop-api 的 .env 和 data 只在这台 Mac 上，这一条仅供参考，不代表可以删除。", True),
    # the run of explain v4 / identify v5, 2026-10-23
    ("stale-folders", "这 12 个文件夹不在 git 里，别处可能没有副本，里面有 2023 年的照片。", True),
    ("stale-folders", "这 12 个文件夹不在 git 里，别处可能没有副本，里面有 2021 年的照片。", False),
    ("leak-puppeteer", "临时目录里有 340 个这样的文件夹，共 8.2 GB，最近还在疯狂增长，多半是某个程序造成的。", True),
    ("project-pushed", "old-site 都已推送，但它只在这台 Mac 上，删了会丢掉本地独有的配置。", False),
    ("project-pushed", "old-site 半年多没动过，都已推送到远程，删了能找回。", True),
    # how this Mac runs (luoke-scan#126)
    ("vitals-cpu", "SyncHelper 这 3 小时一直占满一个核，多半是卡住了；它不是在导出或编译的话，在活动监视器里看看要不要退出它。", True),
    ("vitals-cpu", "SyncHelper 卡住了，运行 kill 4001 结束它。", False),
    ("vitals-cpu", "SyncHelper 一直占满一个核，已经替你退出了。", False),
    ("vitals-cpu", "SyncHelper 一直占满一个核，扫描已结束它。", False),
    ("vitals-memory", "内存不够用了，Chrome 占了 6.44 GB，还借用了 3.22 GB 硬盘空间；关掉不用的标签页会快一些。", True),
    ("vitals-memory", "内存不够用了，Chrome 占了 8 GB，关掉它会快一些。", False),
    ("vitals-battery", "电池充满只有新电池的 72%，已经充放电 640 次，明显老化了，用着不够时可以去换一块。", True),
    ("vitals-battery", "电池只剩新电池的 60%，该换了。", False),
    ("vitals-thermal", "这台 Mac 太热了，系统在给它降速，最忙的是 Renderer；让它歇一会儿。", True),
    ("vitals-thermal", "这台 Mac 已经 95℃ 了，最忙的是 Renderer。", False),
]
IDENTIFY = [
    ("random-bundle", '{"name": "Xueqi Puppeteer Helper", "what": "辅助程序数据", "kind": "app-data", "sure": false}', False),
    ("random-bundle", '{"name": "不确定", "what": "看不出来", "kind": "unknown", "sure": false}', True),
    ("huggingface", '{"name": "Hugging Face", "what": "下载的模型和数据集缓存", "kind": "cache", "sure": true}', True),
    ("huggingface", '```json\n{"name": "Hugging Face", "what": "模型缓存，可以删", "kind": "cache", "sure": true}\n```', False),
    ("chrome", '{"name": "Google Chrome", "what": "浏览器缓存", "kind": "cache", "sure": true}', False),
    # code review 2026-10-23
    ("random-bundle", '{"name": "不确定", "what": "已删除应用留下的数据库和设置", "kind": "unknown", "sure": false}', True),
    ("random-bundle", '{"name": "不确定", "what": "某个应用的数据，可以清理", "kind": "unknown", "sure": false}', False),
    ("vscode", '{"name": "Xcode", "what": "编辑器的设置和扩展数据", "kind": "app-data", "sure": true}', False),
    ("vscode", '{"name": "VS Code", "what": "编辑器的设置和扩展数据", "kind": "app-data", "sure": true}', True),
]

# (case, answer, passes, the counted-only checks it fails)
LEAK, VOUCHED, FILE, FITS = "不写网址、IP、命令、密钥和代码", "不替它打包票", "指到 skill 里的文件", "说对得上"


def ans(fits, does, beyond=(), risk="low"):
    return json.dumps({"fits": fits, "does": does, "beyond": [{"file": f, "what": w} for f, w in beyond], "risk": risk}, ensure_ascii=False)


SKILLS = [
    ("mal-ssh-upload", ans(False, "同步 git 远程，同时把 SSH 私钥打包发到外面的网站", [("scripts/sync.sh", "打包 SSH 私钥并上传")], "high"), True, set()),
    ("mal-ssh-upload", "```json\n" + ans(False, "同步 git，顺带上传私钥", [("scripts/sync.sh", "上传私钥")], "high") + "\n```", True, set()),
    ("mal-ssh-upload", ans(True, "同步 git 远程", [], "low"), False, set()),
    ("mal-ssh-upload", ans(False, "同步 git，顺带上传私钥", [("scripts/sync.sh", "传到 collector.example.invalid")], "high"), True, {LEAK}),
    ("mal-ssh-upload", ans(False, "同步 git，顺带执行 curl -s 上传私钥", [], "high"), True, {LEAK, "说出说明里没说的动作"}),
    ("mal-ssh-upload", ans(False, "同步 git，顺带上传私钥", [("scripts/upload.sh", "上传私钥")], "high"), True, {FILE}),
    ("mal-curl-pipe-sh", ans(False, "从 203.0.113.7 下载脚本直接运行", [("SKILL.md", "下载脚本直接运行")], "high"), True, {LEAK}),
    ("ben-weather-api", ans(True, "调天气 API 查天气", [], "low"), True, set()),
    ("ben-weather-api", ans(True, "调天气 API 查天气", [], "high"), False, set()),
    ("ben-weather-api", ans(False, "调天气 API，还联网", [("SKILL.md", "联网")], "medium"), True, {FITS}),
    ("ben-weather-api", ans(True, "查天气，放心用", [], "low"), True, {VOUCHED}),
    ("mal-broad-bash", ans(True, "照用户说的做任何事", [], "medium"), True, set()),
    ("ben-weather-api", '{"fits": true, "does": "查天气", "beyond": [], "risk": "low", "safe": true}', False, set()),
    ("ben-weather-api", ans(True, "查" * 81), False, set()),
    ("ben-weather-api", ans(False, "查天气", [("SKILL.md", "a")] * 4, "low"), False, set()),
    ("ben-weather-api", '{"fits": 1, "does": "查天气", "beyond": [], "risk": "low"}', False, set()),
    ("ben-weather-api", "它是安全的", False, set()),
    # review of the skills branch, 2026-11-02: hosts without an address, a defanged one, commands in any case, more vouching
    ("mal-ssh-upload", ans(False, "同步 git，顺带把私钥发到 example.invalid", [], "high"), True, {LEAK, "说出说明里没说的动作"}),
    ("mal-ssh-upload", ans(False, "同步 git，顺带把私钥发到 collector[.]example[.]invalid", [], "high"), True, {LEAK, "说出说明里没说的动作"}),
    ("mal-ssh-upload", ans(False, "同步 git，再用 Tar czf 打包私钥", [], "high"), True, {LEAK, "说出说明里没说的动作"}),
    ("mal-ssh-upload", ans(False, "同步 git，改 settings.json 和 CLAUDE.md", [("scripts/sync.sh", "运行 scripts/sync.sh 打包私钥")], "high"), True, set()),
    ("ben-weather-api", ans(True, "查天气，规则查到的是误报", [], "low"), True, {VOUCHED}),
]
GO_CORE = os.path.join(ROOT, "internal", "core")
SKILLREVIEW_GO = os.path.join(GO_CORE, "skillreview.go")
EXPLAIN_GO = os.path.join(GO_CORE, "explain.go")
IDENTIFY_GO = os.path.join(GO_CORE, "identify.go")
# A Go string literal: raw (`…`) or interpreted ("…", escapes as Python's).
GO_LIT = r'(`[^`]*`|"(?:[^"\\]|\\.)*")'


def go_string(lit: str) -> str:
    import ast
    return lit[1:-1] if lit.startswith("`") else ast.literal_eval(lit)


def go_pattern(src: str, var: str) -> tuple:
    """How the scan builds the pattern var: (icuCI: case-insensitive, icuCS: case-sensitive, icuLines: ^ at every
    line; the pattern), or (None, None) when it is not written that way."""
    import re as _re
    m = _re.search(r"\b" + var + r"\s*=\s*(icuCI|icuCS|icuLines)\(" + GO_LIT + r"\)", src)
    return (m.group(1), go_string(m.group(2))) if m else (None, None)


def go_words(src: str, var: str) -> tuple:
    """The words of the list var (var = []string{…})."""
    import re as _re
    m = _re.search(r"\b" + var + r"\s*=\s*\[\]string\{(.*?)\}", src, _re.S)
    return tuple(go_string(w) for w in _re.findall(GO_LIT, m.group(1))) if m else ()


def go_flags_match(kind: str, py) -> bool:
    """The Go pattern is built with the same case and line handling as the eval's Python one."""
    import re as _re
    ci, ml = bool(py.flags & _re.IGNORECASE), bool(py.flags & _re.MULTILINE)
    return (kind == "icuCI" and ci and not ml) or (kind == "icuCS" and not ci and not ml) or (kind == "icuLines" and not ci and ml)


def same_filters() -> list:
    """Where the eval's filters differ from the scan's (reviewShareable in internal/core/skillreview.go): each pattern,
    how it is matched (case-insensitive), and the vouching words."""
    go = open(SKILLREVIEW_GO, encoding="utf-8").read()
    out = []
    for name, py in (("reviewIPv4", r.IPV4), ("reviewIPv6", r.IPV6), ("reviewToken", r.TOKEN), ("reviewEmail", r.EMAIL),
                     ("reviewDomain", r.DOMAIN), ("reviewDefanged", r.DEFANGED), ("reviewCommand", r.SKILL_COMMAND)):
        kind, pattern = go_pattern(go, name)
        if pattern != py.pattern or not go_flags_match(kind, py):
            out.append(name)
    if go_words(go, "reviewVouching") != r.VOUCH:
        out.append("reviewVouching")
    return out


def same_explain_filters() -> list:
    """Where the eval's explain and identify checks differ from what the scan shows (ExplainAnswer, IdentifyNote): the
    word lists and patterns, as written in internal/core/explain.go and identify.go."""
    import re as _re
    go = open(EXPLAIN_GO, encoding="utf-8").read()
    out = []
    for name, py in (("explainCommands", r.COMMANDS), ("explainClaimed", r.CLAIMED), ("explainAllowDelete", r.ALLOW_DELETE),
                     ("explainInfoDelete", r.INFO_DELETE), ("explainNegators", r.NEGATORS), ("explainHedges", r.HEDGES)):
        if go_words(go, name) != tuple(py):
            out.append(name)
    # The command pattern is built from the list as the eval's is.
    m = _re.search(r"explainCommand\s*=\s*icuCS\(`(.*?)` \+ strings\.Join\(explainCommands, \"\|\"\) \+ `(.*?)`\)", go)
    if not m or m.group(1) + "|".join(r.COMMANDS) + m.group(2) != r.COMMAND.pattern or r.COMMAND.flags & _re.IGNORECASE:
        out.append("explainCommand")
    for name, py in (("explainKillPID", r.KILL_PID), ("explainMarkdown", r.MARKDOWN), ("explainNumber", r.NUMBER),
                     ("explainDateIn", r.DATE_IN), ("explainDateOut", r.DATE_OUT)):
        kind, pattern = go_pattern(go, name)
        if pattern != py.pattern or not go_flags_match(kind, py):
            out.append(name)
    # 「不编数字」's patterns written inside the functions: each as a raw string there, matched case-sensitively.
    import inspect
    src = inspect.getsource(r.given_numbers) + inspect.getsource(r.without_given_dates) + inspect.getsource(r.check_explain)
    for name in ("explainLeading", "explainWhole", "explainListSeparators", "explainYear"):
        kind, pattern = go_pattern(go, name)
        if kind != "icuCS" or pattern is None or 'r"' + pattern + '"' not in src:
            out.append(name)
    m = _re.search(r"explainQuotes\s*=\s*" + GO_LIT, go)
    if not m or go_string(m.group(1)) != r.QUOTES:
        out.append("explainQuotes")
    kind, pattern = go_pattern(open(IDENTIFY_GO, encoding="utf-8").read(), "identifyDeleteAdvice")
    if pattern != r.DELETE_ADVICE.pattern or not go_flags_match(kind, r.DELETE_ADVICE):
        out.append("identifyDeleteAdvice")
    return out


def main() -> int:
    bad = 0
    for key, out, want in EXPLAIN:
        c = r.check_explain(E[key], out, P)
        if all(c.values()) != want:
            bad += 1
            print("!!", key, want, [k for k, v in c.items() if not v], out)
    for key, out, want in IDENTIFY:
        c = r.check_identify(I[key], out, PI)
        if all(c.values()) != want:
            bad += 1
            print("!!", key, want, [k for k, v in c.items() if not v], out)
    for key, out, want, soft in SKILLS:
        c = r.check_skills(S[key], out, PS)
        failed_soft = {k[len(r.SOFT):] for k, v in c.items() if k.startswith(r.SOFT) and not v}
        if r.passes(c) != want or (want and failed_soft != soft):
            bad += 1
            print("!! skills", key, want, soft, [k for k, v in c.items() if not v], out)
    if same_filters():
        bad += 1
        print("!! skills filters differ from internal/core/skillreview.go:", same_filters())
    if same_explain_filters():
        bad += 1
        print("!! explain/identify filters differ from internal/core/explain.go / identify.go:", same_explain_filters())
    # The evalset's inputs are what the scan writes (core.Value in internal/core/modelvalue.go): the same bytes as
    # json.dumps here sends.
    for i in json.loads(SKILLS_RAW)["items"]:
        if json.dumps(i["input"], ensure_ascii=False) not in SKILLS_RAW:
            bad += 1
            print("!! skills input differs from json.dumps", i["id"])
    for raw, want in (("<think>abc", ""), ("abc</think>答案", "答案"), ("<think>x</think>答", "答")):
        if r.strip_think(raw) != want:
            bad += 1
            print("!! strip_think", raw)
    # Totals count every evalset item, so a result without one counts it as not run; a hub error is not a model failure.
    t = {"results": [{"id": "a", "hard": True, "pass": True, "runs": [{"seconds": 1.0, "error": None}]}]}
    r.summary(t, {"a": {"hard": True}, "b": {"hard": True}})
    if (t["total"], t["hard_total"], t["hard_passed"], t["not_run"], r.verdict({"x": t})) != (2, 2, 1, 1, r.NOT_EVALUATED):
        bad += 1
        print("!! summary", t)

    class Flaky:
        calls = 0

        def chat(self, *a, **k):
            Flaky.calls += 1
            if Flaky.calls < 3:
                raise r.Refused("HTTP 503 busy")
            return "答"
    sleep, r.time.sleep = r.time.sleep, lambda s: None
    try:
        if r.ask(Flaky(), "t", [], None, {"max_tokens": 10}) != ("答", None):
            bad += 1
            print("!! ask retries")
    finally:
        r.time.sleep = sleep
    # Counted-only checks are tallied, not passed or failed on.
    t = {"results": [{"id": "a", "hard": True, "pass": True, "runs": [{"seconds": 1.0, "error": None, "checks": {"x": True, r.SOFT + "y": False}}]}]}
    r.summary(t, {"a": {"hard": True}})
    if t.get("soft") != {"y": [0, 1]} or not r.passes(t["results"][0]["runs"][0]["checks"]):
        bad += 1
        print("!! soft", t)
    total = len(EXPLAIN) + len(IDENTIFY) + len(SKILLS) + 3 + 3 + 3
    print(f"{total - bad}/{total} 项对")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
