#!/usr/bin/env python3
"""对着 luoke-agent 的参考实现自测 MCP：只查假用户目录，什么都不碰真实的 Mac。

用 luoke-agent 仓库里的 `luoke_agent/mcp.py`（ToolClient）和 `luoke_agent/a2ui.py`（卡片校验），
照 agent 的做法走一遍：发现、列工具、读 outbox、校验每张卡片、没点按的改动被拒、点按后执行、结果卡片能更新原卡片、
办完从 outbox 撤下、放下的急事不再出现、退出删掉 socket 和锁文件。

    python3 scripts/agent_selftest.py --agent-repo <luoke-agent 的目录> [--bin .build/debug/luoke-scan]
        [--serve .build/debug/luoke-scan-serve] [--work <空目录>]
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ACCESSORY = "luoke-scan"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-repo", required=True)
    ap.add_argument("--bin", default=".build/debug/luoke-scan")
    ap.add_argument("--serve", default=".build/debug/luoke-scan-serve", help="只管 socket 的服务；每个请求交给 --bin 那个程序")
    ap.add_argument("--work", help="放假用户目录的空目录（默认新建一个临时目录）")
    ap.add_argument("--keep", action="store_true", help="跑完不删假用户目录")
    a = ap.parse_args()
    sys.path.insert(0, os.path.abspath(a.agent_repo))
    from luoke_agent import a2ui, mcp  # noqa: E402

    work = a.work or tempfile.mkdtemp(prefix="luoke-scan-selftest-")
    fx = os.path.join(work, "fx")
    # sockaddr_un holds ~104 bytes; a long work path gets a short socket directory of its own.
    sock_dir = work if len(work) < 80 else tempfile.mkdtemp(prefix="la-", dir="/tmp")
    sock = os.path.join(sock_dir, "agent.sock")
    binary = os.path.abspath(a.bin)
    manifest = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "packaging", "luoke-accessory.json")))

    passed: list[str] = []
    failed: list[str] = []

    def check(ok: bool, what: str) -> None:
        (passed if ok else failed).append(what)
        print(("  ok  " if ok else "  !!  ") + what)

    def run(*args: str) -> None:
        subprocess.run([binary, *args], check=True, stdout=subprocess.DEVNULL)

    def click(surface, cid: str) -> tuple:
        name, ctx = surface.find_action(cid)
        action = {"surfaceId": surface.surface_id, "componentId": cid,
                  "at": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
        return name, ctx, action

    def button(surface, event: str, label_part: str = "") -> str:
        for cid, c in surface.components.items():
            if c.get("component") != "Button" or c["action"]["event"]["name"] != event:
                continue
            text = surface.components.get(c["child"], {}).get("text", "")
            if label_part in text:
                return cid
        raise KeyError(f"卡片上没有 {event}（{label_part}）按钮")

    run("fixture", fx)
    run("update", "--data", os.path.join(fx, "data"), "--tool-dir", os.path.join(fx, "tools"), "--force")
    server = subprocess.Popen([os.path.abspath(a.serve), "--fixture", fx, "--socket", sock], stdout=subprocess.DEVNULL)
    try:
        client = mcp.ToolClient(sock, client_version="selftest")
        deadline = time.time() + 120
        while True:
            try:
                info = client.discover()
                break
            except mcp.NotRunning:
                if time.time() > deadline or server.poll() is not None:
                    raise SystemExit("服务没起来")
                time.sleep(0.5)

        print("连接")
        check(info.get("supportedVersions") == [mcp.PROTOCOL_VERSION], "server/discover 认 2026-07-28")
        st = os.stat(sock)
        check(oct(st.st_mode & 0o777) == "0o600" and oct(os.stat(sock_dir).st_mode & 0o777) == "0o700", "socket 600、目录 700")

        print("工具")
        tools = {t["name"]: t for t in client.list_tools()}
        writes = {n for n, t in tools.items() if not t["annotations"]["readOnlyHint"]}
        declared = {x["name"] for x in manifest["capabilities"]["actions"]}
        check(writes == declared, f"会改动东西的工具和配件清单的 actions 一致：{sorted(writes)}")
        check(not any(n.startswith("agent.") for n in tools), "没有 agent. 开头的工具名")

        print("概览、权限、基础页（luoke-agent#3）")
        summary = client.read_json("summary")
        check(isinstance(summary.get("count"), int) and isinstance(summary.get("text"), str), f"summary：{summary}")
        perms = client.read_json("permissions")
        declared_perms = {p["id"] for p in manifest["capabilities"]["permissions"]}
        check(set(perms) == declared_perms and all(v in ("granted", "denied", "on", "off", "ask") for v in perms.values()),
              f"permissions 和清单一致：{perms}")
        for page in manifest["capabilities"]["service"]["pages"]:
            msgs = client.read_json("page/" + page["id"])
            problems = a2ui.validate(msgs)
            check(not problems, f"page/{page['id']} 通过 a2ui 校验 {problems or ''}")

        check(client.read_json("outbox") == client.read_json(f"luoke://{ACCESSORY}/outbox"), "outbox 两种写法读出来一样")
        switch = {"surfaceId": "page-overview", "componentId": "selftest",
                  "at": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
        r = client.call_tool("scan_autoclean", {"on": False}, user_action=switch)
        check(not r.is_error and client.read_json("permissions").get("auto") == "off", "点了关掉，权限状态变成 off")
        r = client.call_tool("scan_autoclean", {}, user_action=switch)
        check(r.is_error and r.code == "invalid", "开关不给 on 被拒")
        client.call_tool("scan_autoclean", {"on": True}, user_action=switch)

        print("outbox")
        items = client.outbox(ACCESSORY)
        kinds = {i["kind"] for i in items}
        reports = {r["kind"] for r in manifest["capabilities"]["reports"]}
        check(kinds <= reports, f"种类都在清单的 reports 里：{sorted(kinds)}")
        check({"security", "findings"} <= kinds, "假用户目录里有报毒和扫描结果")
        for i in items:
            missing = [k for k in ("id", "kind", "urgency", "created", "why_now", "title", "summary", "card") if not i.get(k) and i.get(k) != []]
            check(not missing, f"{i['id']} 字段齐全 {missing or ''}")
            problems = a2ui.validate(i["card"])
            check(not problems, f"{i['id']} 的卡片通过 a2ui 校验 {problems or ''}")
        check(all(i["urgency"] == "urgent" for i in items if i["kind"] == "security"), "报毒是 urgent")
        findings = next(i for i in items if i["kind"] == "findings")
        check(findings["urgency"] == "low" and bool(findings["expires"]), "扫描结果是 low、带 expires")

        print("执行方案")
        surface = a2ui.build(findings["card"])
        name, ctx, action = click(surface, button(surface, "scan_apply"))
        r = client.call_tool(name, ctx)
        check(r.is_error and r.code == "needs_user_action", "没点按就调 scan_apply 被拒")
        r = client.call_tool(name, ctx, user_action=action)
        check(not r.is_error and "移到废纸篓" in r.text, f"点按后执行：{r.text}")
        check(r.done, "答复带 done")
        try:
            a2ui.update(surface, r.card)
            check(True, "结果卡片能更新原卡片")
        except a2ui.CardError as e:
            check(False, f"结果卡片能更新原卡片 {e.problems}")
        trash = os.listdir(os.path.join(fx, "Trash")) if os.path.isdir(os.path.join(fx, "Trash")) else []
        check(any(n.endswith("-pip") for n in trash), "pip 缓存挪进了假目录里的 Trash")
        check(os.path.isdir(os.path.join(fx, "home", "Projects", "old-pushed")), "要确认的默认不动")
        check(not any(i["id"] == findings["id"] for i in client.outbox(ACCESSORY)), "办完从 outbox 撤下")

        print("报毒")
        sec = next(i for i in client.outbox(ACCESSORY) if i["kind"] == "security" and "eicar" in i["title"])
        surface = a2ui.build(sec["card"])
        name, ctx, action = click(surface, button(surface, "scan_apply", "废纸篓"))
        r = client.call_tool(name, ctx, user_action=action)
        check(not r.is_error and not os.path.exists(os.path.join(fx, "home", "Downloads", "eicar-test.com")), f"一点就移走：{r.text}")
        other = next((i for i in client.outbox(ACCESSORY) if i["kind"] == "security"), None)
        if other:
            client.call_tool("outbox_ack", {"id": other["id"], "state": "dismissed"})
            check(not any(i["id"] == other["id"] for i in client.outbox(ACCESSORY)), "放下的急事不再出现")

        print("只读的工具（对话里问的，答一张新卡片）")
        for tool, args in (("scan_status", {}), ("scan_findings", {"verdict": "confirm", "limit": 10}), ("scan_plan", {"scope": "all"})):
            r = client.call_tool(tool, args)
            card = r.card
            ok = not r.is_error and (card is None or (card[0].get("createSurface") is not None and not a2ui.validate(card)))
            check(ok, f"{tool}：{r.text.splitlines()[0] if r.text else ''}")
        r = client.call_tool("scan_ignore", {"finding_id": "x"})
        check(r.is_error and r.code == "needs_user_action", "没点按就调 scan_ignore 被拒")

        print("现在查一下（另起一个进程查，请求马上答）")
        report = os.path.join(fx, "data", "last-report.json")
        before = os.stat(report).st_mtime
        t0 = time.time()
        r = client.call_tool("scan_now", {})
        check(not r.is_error and time.time() - t0 < 5, f"马上答：{r.text}")
        while os.stat(report).st_mtime == before and time.time() - t0 < 120:
            time.sleep(0.5)
        check(os.stat(report).st_mtime != before, "查完写了新的报告")
    finally:
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
    check(not os.path.exists(sock), "退出时删掉 socket")
    check(not os.path.exists(sock + ".lock"), "退出时删掉锁文件")
    if sock_dir != work:
        shutil.rmtree(sock_dir, ignore_errors=True)
    if not a.keep and not a.work:
        shutil.rmtree(work, ignore_errors=True)
    print(f"\n{len(passed)} 项通过，{len(failed)} 项没过")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
