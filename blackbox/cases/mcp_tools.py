"""MCP 的协议和每个工具，以及会动文件时的安全用例：查过以后改过的、换过的、路上有链接的、已经不在的不动；放回时原位置
有同名的放旁边、废纸篓倒掉了照实说、废纸篓里换了一个不认、原来的文件夹换成了链接不放。"""
from __future__ import annotations

import datetime
import json
import os

from agent import OUTBOX, Agent, resolve, surface_id
from cases.rules_space import bulk
from fx import LOCAL, MiB, T0, days, iso
from harness import PROTOCOL, Run, case


def at(minutes: int) -> datetime.datetime:
    return T0 + datetime.timedelta(minutes=minutes)


def small(r: Run, *, malware: bool = False) -> None:
    """一份小的假目录，查过一轮：pip 的缓存 60 MiB（放心删）、25 个 wings-* 临时文件夹（要确认），可以加一个报毒的下载。"""
    fx = r.fx
    bulk(fx, "~/Library/Caches/pip/http", 60 * MiB, at=days(3), chunk=20 * MiB)
    fx.touch("~/Library/Caches/pip", days(3))
    for i in range(25):
        d = f"$TMPDIR/wings-A{i:05d}"
        fx.file(d + "/index.html", size=5 * MiB, at=days(2 + i % 4))
        fx.touch(d, days(2 + i % 4))
    if malware:
        fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    r.update()
    r.scan(T0)


def ua(a: Agent, surface: str = "chat", component: str = "button") -> dict:
    return {"surfaceId": surface, "componentId": component, "at": a.clock.astimezone(LOCAL).isoformat(timespec="seconds")}


def plan_on_card(a: Agent) -> dict:
    """一轮的卡片上「按这个处理」按钮带的方案（plan_id 和默认的选项），另加 options：每一项能选的值。"""
    a.read(OUTBOX)
    s = a.surfaces[surface_id(a.item("findings")["card"])]
    _, ctx = s.button("scan_apply", "")
    p = resolve(ctx, s.data)
    p["options"] = s.options()
    return p


def clear_all(p: dict) -> dict:
    """每一项都选「清掉」：移到废纸篓，会重建的缓存是删掉。"""
    return {k: [p["options"][k][0]] for k in p["choices"]}


# ================================================================ 协议

@case("mcp/protocol/errors", "坏的 JSON、通知（不答）、协议版本不对、不认识的方法、工具、资源、参数不对：各答各的错，不动任何东西")
def protocol_errors(r: Run) -> None:
    small(r)
    r.mcp_raw("{not json", clock=at(1))
    r.mcp_raw(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}), clock=at(1), note="通知：不答")
    r.mcp("tools/list", clock=at(1), protocol="2025-06-18", note="协议版本不对")
    r.mcp("no/such/method", clock=at(1))
    r.mcp("tools/call", {"name": "no_such_tool", "arguments": {}}, clock=at(1))
    r.mcp("resources/read", {"uri": "page/nope"}, clock=at(1))
    r.mcp("tools/call", {"name": "scan_findings", "arguments": {"verdict": "bogus"}}, clock=at(1))
    r.mcp("tools/call", {"name": "scan_findings", "arguments": {"limit": 0}}, clock=at(1))


@case("mcp/protocol/needs-click", "会改动东西的四个工具没有用户点按（ai.luoke/user-action）一律拒绝，文件一个不动")
def protocol_needs_click(r: Run) -> None:
    small(r)
    a = Agent(r, at(1))
    p = plan_on_card(a)
    a.call("scan_apply", {"plan_id": p["plan_id"], "choices": clear_all(p)})
    a.call("scan_ignore", {"finding_id": "leak.temp-prefix/000000000000"})
    a.call("scan_restore", {"id": "p-000000000000"})
    a.call("scan_autoclean", {"on": True})


# ================================================================ 只读的工具

@case("mcp/tools/no-report", "还没查过：状态、发现、outbox、概览、权限、基础页都说还没查过")
def no_report(r: Run) -> None:
    a = Agent(r, at(1))
    a.look()
    a.call("scan_status")
    a.call("scan_findings")
    a.call("scan_plan")


@case("mcp/tools/findings", "按结论、类别筛发现，限几条；scan_plan 出全部的和只出缓存的方案")
def findings(r: Run) -> None:
    small(r, malware=True)
    a = Agent(r, at(1))
    a.call("scan_status")
    a.call("scan_findings")
    a.call("scan_findings", {"verdict": "safe"})
    a.call("scan_findings", {"verdict": "confirm", "limit": 1})
    a.call("scan_findings", {"category": "malware"})
    a.call("scan_plan")
    a.call("scan_plan", {"scope": "cache"})


@case("mcp/tools/reveal-settings", "在访达里显示、打开系统设置：假目录里不真打开，记下要跑的命令；编号、名字不对的答错")
def reveal_settings(r: Run) -> None:
    small(r, malware=True)
    a = Agent(r, at(1))
    a.read(OUTBOX)
    eicar = a.item("security", "eicar")
    fid = [b for b in json.dumps(eicar["card"]).split('"') if b.startswith("malware.clamav/")][0]
    a.call("scan_reveal", {"finding_id": fid})
    a.call("scan_reveal", {"finding_id": "malware.clamav/000000000000"})
    a.call("scan_open_settings", {"grant": "fda"})
    a.call("scan_open_settings", {"grant": "登录项"})
    a.call("scan_open_settings", {"grant": "nope"})


@case("mcp/tools/outbox-ack", "记下说过了：shown 还留着，answered、dismissed 从 outbox 撤下；放下的报毒下一轮也不再是急事")
def outbox_ack(r: Run) -> None:
    small(r, malware=True)
    a = Agent(r, at(1))
    a.read(OUTBOX)
    eicar = a.item("security", "eicar")["id"]
    a.call("outbox_ack", {"id": eicar, "state": "shown"})
    a.read(OUTBOX)
    a.call("outbox_ack", {"id": eicar, "state": "dismissed"})
    a.read(OUTBOX)
    a.read("summary")
    a.call("outbox_ack", {"id": "security/nope", "state": "shown"})
    a.call("outbox_ack", {"id": eicar, "state": "maybe"})
    r.scan(at(60), note="下一轮")
    a.at(at(61)).read(OUTBOX)


@case("mcp/tools/scan-now", "现在查一下：马上答（另起一轮只读的，不自动清），查完 outbox 换成新的一轮")
def scan_now(r: Run) -> None:
    small(r)
    a = Agent(r, at(1))
    a.read(OUTBOX)
    r.fx.file("~/Downloads/eicar-new.com", size=68, at=at(-30))
    r.note("下载里来了一个报毒的文件")
    a.at(at(5)).call("scan_now")
    a.wait_round(at(5))
    a.read(OUTBOX)
    a.call("scan_status")


# ================================================================ 会动文件的

@case("mcp/apply/choices", "一份方案里移到废纸篓、先不动、以后别提各选一项；同一份方案再点一次照做一遍（移走了的算不在了）；方案编号、选项不对的拒绝")
def apply_choices(r: Run) -> None:
    small(r, malware=True)
    a = Agent(r, at(1))
    p = plan_on_card(a)
    keys = sorted(p["choices"])
    choices = {k: [p["options"][k][[0, -2, -1][i % 3]]] for i, k in enumerate(keys)}   # 清掉、先不动、以后别提
    a.at(at(2)).call("scan_apply", {"plan_id": p["plan_id"], "choices": choices}, user_action=ua(a))
    a.call("scan_apply", {"plan_id": p["plan_id"], "choices": choices}, user_action=ua(a), note="同一份方案再点一次")
    a.call("scan_apply", {"plan_id": "p-000000000000", "choices": choices}, user_action=ua(a))
    a.call("scan_apply", {"plan_id": p["plan_id"], "choices": {keys[0]: ["shred"]}}, user_action=ua(a))
    if any("remove" in o for o in p["options"].values()):
        cache = [k for k, o in p["options"].items() if "remove" in o][0]
        a.call("scan_apply", {"plan_id": p["plan_id"], "choices": {cache: ["trash"]}}, user_action=ua(a), note="缓存只能删掉，不能移到废纸篓")
    a.read(OUTBOX)
    a.read("page/cleaned")
    r.scan(at(60), note="下一轮：以后别提的那条不再报")


@case("mcp/apply/changed-since-scan", "查过以后改过的、换过的（inode 不同）、已经不在的：不动；改过的照实说，不在的算办完")
def apply_changed(r: Run) -> None:
    small(r)
    a = Agent(r, at(1))
    p = plan_on_card(a)
    fx = r.fx
    fx.file("$TMPDIR/wings-A00000/index.html", size=5 * MiB, at=at(1))        # 查过以后又写过
    fx.remove("$TMPDIR/wings-A00001")
    fx.file("$TMPDIR/wings-A00001/index.html", size=5 * MiB, at=days(3))     # 删了重建：同名、更老，但不是同一个
    fx.touch("$TMPDIR/wings-A00001", days(3))
    fx.remove("$TMPDIR/wings-A00002")                                        # 已经不在了
    r.note("wings-A00000 刚写过；wings-A00001 删了重建；wings-A00002 删了")
    a.at(at(2)).call("scan_apply", {"plan_id": p["plan_id"], "choices": clear_all(p)}, user_action=ua(a))


@case("mcp/apply/links-on-path", "缓存所在的 ~/Library/Caches 换成了链接：不删、不移，留到下一轮；临时目录里的一个文件夹换成链接：不跟着走")
def apply_links(r: Run) -> None:
    small(r)
    a = Agent(r, at(1))
    p = plan_on_card(a)
    fx = r.fx
    os.rename(fx.p("~/Library/Caches"), fx.p("~/Library/Caches-real"))
    os.symlink(fx.p("~/Library/Caches-real"), fx.p("~/Library/Caches"))
    elsewhere = fx.dir("elsewhere/wings-A00003")
    fx.file("elsewhere/wings-A00003/keep.txt", "not ours\n")
    fx.remove("$TMPDIR/wings-A00003")
    os.symlink(elsewhere, fx.p("$TMPDIR/wings-A00003"))
    r.note("~/Library/Caches 挪开、原处放一个指过去的链接；wings-A00003 换成指向假目录外的链接")
    a.at(at(2)).call("scan_apply", {"plan_id": p["plan_id"], "choices": clear_all(p)}, user_action=ua(a))


# ================================================================ 放回

def trashed(r: Run, *, dup: bool = False) -> Agent:
    """都选清掉点一次：pip 的缓存删掉（记下、放不回），25 个 wings-* 进了废纸篓；dup：下载里一份重复的也移走。"""
    if dup:
        report = bytes((i * 7) & 0xFF for i in range(2 * MiB))
        r.fx.file("~/Documents/report.pdf", report, at=days(40))
        r.fx.file("~/Downloads/nested/report.pdf", report, at=days(20))
    small(r)
    a = Agent(r, at(1))
    p = plan_on_card(a)
    a.at(at(2)).call("scan_apply", {"plan_id": p["plan_id"], "choices": clear_all(p)}, user_action=ua(a))
    a.read("page/cleaned")
    return a


def cleaned_ids(r: Run) -> tuple:
    """清理记录里的编号：(移进废纸篓、能放回的, 直接删的)。"""
    out = r.cli("cleaned", "--fixture", r.fx.root, "--json", json_out=True)
    return [e["id"] for e in out if e.get("trashed")], [e["id"] for e in out if not e.get("trashed")]


@case("mcp/restore/occupied", "原位置又有了同名的：放在旁边，不盖掉（整批放回只放移进废纸篓的，删掉的缓存不在里面）")
def restore_occupied(r: Run) -> None:
    a = trashed(r)
    r.fx.file("$TMPDIR/wings-A00000/index.html", size=1024, at=at(3))
    r.note("测试又建了一个 wings-A00000")
    a.at(at(10)).click("scan_restore", page="cleaned")
    a.read("page/cleaned")


@case("mcp/restore/trash-emptied", "废纸篓倒掉了：照实说放不回")
def restore_emptied(r: Run) -> None:
    a = trashed(r)
    for n in os.listdir(r.fx.p("Trash")):
        r.fx.remove("Trash/" + n)
    r.note("废纸篓倒掉了")
    a.at(at(10)).click("scan_restore", page="cleaned")
    a.read("page/cleaned")


@case("mcp/restore/trash-swapped", "废纸篓里那一项换成了一个同名的别的东西：不认，不放回")
def restore_swapped(r: Run) -> None:
    a = trashed(r)
    for n in os.listdir(r.fx.p("Trash")):
        r.fx.remove("Trash/" + n)
        r.fx.file("Trash/" + n + "/other", "someone else's\n", at=at(3))
    r.note("废纸篓里那一项换成了同名的别的东西")
    a.at(at(10)).click("scan_restore", page="cleaned")


@case("mcp/restore/parent-linked", "原来的文件夹换成了指到别处的链接：不放回去，没放回的列在最前面；没了的就补建（只给自己），之前放回过的分开说")
def restore_parent_linked(r: Run) -> None:
    a = trashed(r, dup=True)
    fx = r.fx
    os.rename(fx.p("~/Downloads/nested"), fx.p("~/Downloads/nested-real"))
    os.symlink(fx.p("~/Downloads/nested-real"), fx.p("~/Downloads/nested"))
    r.note("~/Downloads/nested 换成了链接")
    a.at(at(10)).click("scan_restore", page="cleaned")
    os.remove(fx.p("~/Downloads/nested"))
    fx.remove("~/Downloads/nested-real")
    r.note("~/Downloads/nested 整个没了")
    a.at(at(11)).click("scan_restore", page="cleaned")


@case("mcp/restore/cli", "命令行看清理记录、按编号放回；再放一次说之前放回过了；直接删的缓存放不回、编号不对的：退出码 1")
def restore_cli(r: Run) -> None:
    trashed(r)
    back, deleted = cleaned_ids(r)
    r.cli("cleaned", "--fixture", r.fx.root)
    r.cli("restore", "--fixture", r.fx.root, back[0])
    r.cli("restore", "--fixture", r.fx.root, back[0])
    r.cli("restore", "--fixture", r.fx.root, deleted[0])
    r.cli("restore", "--fixture", r.fx.root, "c-000000000000")
    r.cli("cleaned", "--fixture", r.fx.root)


def dups(r: Run) -> None:
    """文稿里一份、下载里一份内容一样的 2 MiB 文件（下载里那份后来的），另有三份一样的，查一轮。"""
    a = bytes((i * 13) & 0xFF for i in range(2 * MiB))
    r.fx.file("~/Documents/report.pdf", a, at=days(40))
    r.fx.file("~/Downloads/report.pdf", a, at=days(20))
    b = bytes((i * 17) & 0xFF for i in range(2 * MiB))
    for rel, d in (("~/Pictures/trip.mov", 60), ("~/Movies/trip.mov", 50), ("~/Desktop/trip.mov", 30)):
        r.fx.file(rel, b, at=days(d))
    r.update()
    r.scan(T0)


@case("mcp/apply/clone", "重复的文件换成克隆：几份都还在、内容一样、不再多占；下一轮不再报重复")
def apply_clone(r: Run) -> None:
    dups(r)
    a = Agent(r, at(1))
    p = plan_on_card(a)
    choices = {k: (["clone"] if "clone" in o else ["keep"]) for k, o in p["options"].items()}
    a.at(at(2)).call("scan_apply", {"plan_id": p["plan_id"], "choices": choices}, user_action=ua(a))
    for rel in ("~/Documents/report.pdf", "~/Downloads/report.pdf", "~/Pictures/trip.mov", "~/Movies/trip.mov", "~/Desktop/trip.mov"):
        assert os.path.exists(r.fx.p(rel)), rel
    r.note("五个文件都还在")
    r.scan(at(60), note="下一轮：克隆不算多占")


@case("mcp/apply/clone-changed", "要留的那份查过以后改过、要换的那份被换成了别的：都不换，照实说")
def apply_clone_changed(r: Run) -> None:
    dups(r)
    a = Agent(r, at(1))
    p = plan_on_card(a)
    choices = {k: (["clone"] if "clone" in o else ["keep"]) for k, o in p["options"].items()}
    r.fx.file("~/Documents/report.pdf", b"changed", at=at(1))
    r.fx.remove("~/Desktop/trip.mov")
    r.fx.file("~/Desktop/trip.mov", bytes((i * 17) & 0xFF for i in range(2 * MiB)), at=days(30))
    r.note("文稿里那份改了；桌面那份删了重建（一样的内容，不是同一个文件）")
    a.at(at(2)).call("scan_apply", {"plan_id": p["plan_id"], "choices": choices}, user_action=ua(a))
