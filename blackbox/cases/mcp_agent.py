"""agent 看到的：照 fixtures/agent 的 5 个场景，在 Python 造的假目录上一步一步问 `luoke-scan mcp`、照卡片点按。
每一步前后比一遍假目录，移进废纸篓、放回的都记在 golden 里。"""
from __future__ import annotations

import datetime
import os

from agent import OUTBOX, Agent
from cases.base import build
from fx import LOCAL, MiB, T0, Fx, days
from harness import Failed, Run, case

# 去掉这些，一轮的方案只剩三项：pip 的缓存（放心删）、测试留下的 25 个 wings-* 临时文件夹、推送过的老项目（要确认）。
PLAIN_REMOVED = [
    "~/Downloads/eicar-test.com",
    "~/Downloads/update.scpt",
    "~/Library/LaunchAgents/io.example.gone.plist",
    "~/Library/Application Support/io.example.removed",
    "~/Library/Preferences/io.example.removed.plist",
    "~/Library/Group Containers/ABCDE12345.io.example.removed",
    "~/Library/Containers/ABCDE12345.io.example.removed",
]


def at(minutes: int) -> datetime.datetime:
    return T0 + datetime.timedelta(minutes=minutes)


def prepared(r: Run, *, remove: bool = False, auto_kinds: bool = False, no_fda: bool = False) -> None:
    """基础假目录：3 天前查过一轮（pip 的缓存还空着），之后 pip 长到 60 MB；可以去掉 PLAIN_REMOVED、加上另外三类不用点就清的。"""
    fx = r.fx
    build(fx)
    r.update()
    r.scan(days(3), note="3 天前查过一轮：pip 的缓存还是空的")
    fx.file("~/Library/Caches/pip/http/blob", size=60 * MiB, at=days(0.5))
    changes = ["pip 的缓存长到 60 MB"]
    if remove:
        for p in PLAIN_REMOVED:
            fx.remove(p)
        changes.append("去掉了报毒的两个文件、坏了的 LaunchAgent、删了的应用留下的数据")
    if auto_kinds:
        add_auto_kinds(fx)
        changes.append("加了装好了的应用的安装包、文稿里也有一份的下载、21 个 Puppeteer 临时文件夹（都是 20 天前来的）")
    if no_fda:
        os.chmod(fx.p(Fx.TCC), 0)
        changes.append("TCC 的数据库读不了（没有完全磁盘访问时 macOS 也不让读）")
    r.note("；".join(changes))


def add_auto_kinds(fx: Fx) -> None:
    """另外三类不用点就清的各一份，20 天前来的：装好了的应用的安装包（带下载标记、临时签名）、文稿里也有一份的下载、
    Puppeteer 留下的 21 个临时文件夹。"""
    old = days(20)
    fx.app("~/Applications/Fixtureapp.app", "io.example.fixtureapp", "Fixtureapp", "2.0", at=old)
    fx.file("~/Downloads/Fixtureapp-2.0.dmg", size=6 * MiB, fill=7, at=old)
    fx.quarantine("~/Downloads/Fixtureapp-2.0.dmg")
    fx.adhoc_sign("~/Downloads/Fixtureapp-2.0.dmg")    # 规则只认有签名的安装包
    report = bytes((i * 31) & 0xFF for i in range(2 * MiB))
    fx.file("~/Documents/report-2026.pdf", report, at=old)
    fx.file("~/Downloads/report-2026.pdf", report, at=old)
    for i in range(21):
        d = f"$TMPDIR/puppeteer_dev_chrome_profile-P{i:05d}"
        fx.file(d + "/Default/Cache/data_0", size=5 * MiB, at=old)
        fx.file(d + "/Local State", "{}", at=old)
        for sub in (d + "/Default/Cache", d + "/Default", d):
            fx.touch(sub, old)


def ua(a: Agent, surface: str, component: str) -> dict:
    """用户在设置之类的地方点的（不是某张卡片）。"""
    return {"surfaceId": surface, "componentId": component, "at": a.clock.astimezone(LOCAL).isoformat(timespec="seconds")}


@case("mcp/agent/first-run-no-fda", "第一次扫描，还没给完全磁盘访问：连上、读 outbox、概览、权限、基础页，问一句扫描的状态", quiet=False)
def first_run_no_fda(r: Run) -> None:
    fx = r.fx
    build(fx)
    fx.file("~/Library/Caches/pip/http/blob", size=60 * MiB, at=days(0.5))
    os.chmod(fx.p(Fx.TCC), 0)
    r.note("pip 的缓存 60 MB；TCC 的数据库读不了")
    r.update()
    r.scan(T0, "--no-full-disk-access", note="主控的空闲任务查第一轮（没有完全磁盘访问）")
    a = Agent(r, at(1), no_fda=True)
    a.connect()
    a.look()
    a.call("scan_status")


@case("mcp/agent/decide-3", "要你决定 3 项的清理方案：照默认的选项点「按上面的选择清理」，pip 的缓存移进废纸篓", quiet=False)
def decide_3(r: Run) -> None:
    prepared(r, remove=True)
    r.scan(T0)
    a = Agent(r, at(1))
    a.connect()
    a.look()
    a.call("scan_findings", {"verdict": "confirm"})
    a.at(at(5)).click("scan_apply", item=a.item("findings"))
    a.read(OUTBOX)
    a.read("summary")


@case("mcp/agent/malware", "下载里有报毒的文件：记下说过了、移到废纸篓、另一个说不是病毒以后别提、又撤销", quiet=False)
def malware(r: Run) -> None:
    prepared(r)
    r.scan(T0)
    a = Agent(r, at(1))
    a.connect()
    a.look()
    a.at(at(2)).call("outbox_ack", {"id": a.item("security", "eicar")["id"], "state": "shown"})
    a.click("scan_apply", "废纸篓", item=a.item("security", "eicar"))
    scpt = a.item("security", "update.scpt")
    a.click("scan_ignore", item=scpt)
    a.read(OUTBOX)
    a.at(at(3)).click("scan_ignore", "撤销", item=scpt)   # 答复那一行上的「撤销」：照样提醒
    a.read(OUTBOX)
    a.read("summary")


@case("mcp/agent/cleaned-restore", "把临时文件夹也改成移到废纸篓、点「按上面的选择清理」；一小时后在清理记录页上整批放回", quiet=False)
def cleaned_restore(r: Run) -> None:
    prepared(r, remove=True)
    r.scan(T0)
    a = Agent(r, at(1))
    a.read(OUTBOX)
    # 改选项在扫描页上（卡片上只有「清理」）
    a.read("page/overview")
    a.at(at(5)).click("scan_apply", "按上面的选择清理", page="overview", choose={"临时文件": "trash"})
    a.at(at(60)).look()
    a.at(at(65)).click("scan_restore", page="cleaned")
    a.read("page/cleaned")
    a.read("permissions")


@case("mcp/agent/autoclean-done", "打开自动清以后，空闲任务那一轮清了 4 类；放回整批，再点「关掉自动清理」", quiet=False)
def autoclean_done(r: Run) -> None:
    prepared(r, remove=True, auto_kinds=True)
    a = Agent(r, days(0.2))
    a.call("scan_autoclean", {"on": True}, user_action=ua(a, "settings", "autoclean"), note="用户之前在设置里打开了自动清（默认关）")
    r.scan(T0, "--autoclean", note="主控的空闲任务：查完自动清")
    a.at(at(1))
    a.connect()
    a.look()
    a.at(at(10)).click("scan_restore", item=a.item("auto-done"))
    a.read("permissions")
    a.read(OUTBOX)
    a.at(at(11)).click("scan_autoclean", "关掉自动清理", item=a.item("auto-done"))
    a.read("permissions")
    a.read("page/overview")


@case("mcp/agent/data-actions", "agent 自己拼扫描页：只读 data/…；照数据里的方案和键把一类里选中的移到废纸篓、另一类以后别再问，"
      "再照清理记录的批次放回", quiet=False)
def data_actions(r: Run) -> None:
    prepared(r, remove=True, auto_kinds=True)
    r.scan(T0)
    a = Agent(r, at(1))
    a.connect()
    overview = a.read("data/overview")
    ids = [c["id"] for c in overview["reclaimable"]]
    if "temp" not in ids or "duplicate" not in ids:
        raise Failed(f"data/overview 里没有临时文件夹或重复文件：{ids}")
    temp = a.read("data/category?id=temp")["items"]
    if len(temp) < 2:
        raise Failed(f"临时文件夹只有 {len(temp)} 项")
    go = temp[1:]   # 最大的一项取消了
    a.at(at(5)).request("tools/call", {"name": "scan_apply", "arguments": {"plan_id": go[0]["plan"],
                                                                            "choices": {it["key"]: ["trash"] for it in go}}},
                        user_action=ua(a, "overview", "trash-selected"), note="「临时文件夹」里取消最大的一项，其余的移到废纸篓")
    a.read("data/category?id=temp")
    history = a.read("data/history")
    dup = a.read("data/category?id=duplicate")["items"]
    a.at(at(6)).request("tools/call", {"name": "scan_apply", "arguments": {"plan_id": dup[0]["plan"],
                                                                            "choices": {it["key"]: ["ignore"] for it in dup}}},
                        user_action=ua(a, "overview", "ignore-category"), note="「重复文件」这一类以后别再问")
    a.read("data/settings")
    a.read("data/overview")
    a.at(at(10)).request("tools/call", {"name": "scan_restore", "arguments": {"id": history["batches"][0]["batch"]}},
                         user_action=ua(a, "overview", "restore"), note="清理记录里那一批放回")
    a.read("data/history")
    a.read("data/usage")
