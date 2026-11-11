"""照 luoke-agent 的做法和扫描说话：读 outbox、基础页，把卡片（A2UI：组件 + 数据模型）拼起来，用户点按钮时换好上下文、
带上 ai.luoke/user-action 转给工具。每个请求是一次 `luoke-scan mcp`（harness.Run.mcp），都记进 golden。"""
from __future__ import annotations

import datetime
import json
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from fx import LOCAL, iso
from harness import Failed, Run

OUTBOX = "luoke://luoke-scan/outbox"


def texts(comps: Dict[str, dict], cid: str) -> str:
    """按钮上的字：子组件是 Text，或是一行（Icon 加 Text）里的那段字"""
    c = comps.get(cid) or {}
    if c.get("component") == "Row":
        return "".join(texts(comps, k) for k in c.get("children") or [])
    return c.get("text", "") if c.get("component") == "Text" else ""


def get_path(data: Any, path: str) -> Any:
    for part in [p for p in path.split("/") if p]:
        data = data[part]
    return data


def resolve(v: Any, data: dict) -> Any:
    """按钮上下文里的 {"path": …} 换成数据模型里那一处现在的值。"""
    if isinstance(v, dict) and set(v) == {"path"} and isinstance(v["path"], str):
        return json.loads(json.dumps(get_path(data, v["path"])))
    if isinstance(v, dict):
        return {k: resolve(x, data) for k, x in v.items()}
    if isinstance(v, list):
        return [resolve(x, data) for x in v]
    return v


def surface_id(msgs: List[dict]) -> str:
    for m in msgs:
        for k in ("createSurface", "updateComponents"):
            if k in m:
                return m[k]["surfaceId"]
    raise Failed("卡片没有 surfaceId")


class Surface:
    def __init__(self) -> None:
        self.comps: Dict[str, dict] = {}
        self.data: dict = {}

    def apply(self, msgs: List[dict]) -> None:
        for m in msgs:
            if "updateComponents" in m:
                self.comps = {c["id"]: c for c in m["updateComponents"]["components"]}
            elif "updateDataModel" in m:
                self.data = json.loads(json.dumps(m["updateDataModel"]["value"]))

    def buttons(self) -> List[Tuple[str, str, str]]:
        """(组件 id, 事件, 按钮上的字)。"""
        return [(cid, c["action"]["event"]["name"], texts(self.comps, c["child"]))
                for cid, c in self.comps.items() if c.get("component") == "Button"]

    def button(self, event: str, label: str) -> Tuple[str, dict]:
        for cid, c in self.comps.items():
            if c.get("component") == "Button" and c["action"]["event"]["name"] == event and label in texts(self.comps, c["child"]):
                return cid, c["action"]["event"].get("context") or {}
        raise Failed(f"卡片上没有 {event}（{label}）按钮；有的是 {self.buttons()}")

    def options(self) -> Dict[str, List[str]]:
        """每个选项的键（数据模型里 /choices/<键>）和它能选的值，第一个是「清掉」的那个（移到废纸篓或删掉）。"""
        out: Dict[str, List[str]] = {}
        for c in self.comps.values():
            if c.get("component") == "ChoicePicker":
                out[[p for p in c["value"]["path"].split("/") if p][-1]] = [o["value"] for o in c["options"]]
        return out

    def choose(self, label: str, value: str) -> None:
        """用户把标题含 label 的那一项改成 value。"""
        for c in self.comps.values():
            if c.get("component") == "ChoicePicker" and label in c.get("label", ""):
                if value not in [o["value"] for o in c["options"]]:
                    raise Failed(f"「{c['label']}」没有 {value} 这个选项")
                parts = [p for p in c["value"]["path"].split("/") if p]
                d = self.data
                for p in parts[:-1]:
                    d = d.setdefault(p, {})
                d[parts[-1]] = [value]
                return
        raise Failed(f"卡片上没有「{label}」这一项")


class Agent:
    """一个 agent。clock 是现在几点（每个请求都带 --clock）；no_fda：螺壳没有完全磁盘访问。"""

    def __init__(self, r: Run, clock: datetime.datetime, *, no_fda: bool = False):
        self.r, self.clock, self.no_fda = r, clock, no_fda
        self.surfaces: Dict[str, Surface] = {}
        self.outbox_cards: Dict[str, Any] = {}
        self.outbox: List[dict] = []

    def at(self, clock: datetime.datetime) -> "Agent":
        self.clock = clock
        return self

    def request(self, method: str, params: Optional[dict] = None, *, user_action: Optional[dict] = None, note: str = "",
                progress_token: Any = None) -> Any:
        res = self.r.mcp(method, params, clock=self.clock, user_action=user_action, no_fda=self.no_fda, note=note,
                         progress_token=progress_token)
        if isinstance(res, dict) and "error" in res and "jsonrpc" in res:
            return res
        return res

    def read(self, uri: str, note: str = "") -> Any:
        res = self.request("resources/read", {"uri": uri}, note=note)
        if not res or "contents" not in res:
            raise Failed(f"读 {uri} 没读到：{res}")
        value = json.loads(res["contents"][0]["text"])
        if uri == OUTBOX:
            self.outbox = value["items"]
            for it in self.outbox:
                # 和上次读到的卡片一字不差就不重画；点按答复换上的那张留着（luoke-agent 比卡片的 hash）
                sid = surface_id(it["card"])
                if sid not in self.surfaces or self.outbox_cards.get(sid) != it["card"]:
                    self.surfaces.setdefault(sid, Surface()).apply(it["card"])
                self.outbox_cards[sid] = it["card"]
        elif uri.startswith("page/"):
            self.surfaces.setdefault(uri[len("page/"):], Surface()).apply(value)
        return value

    def connect(self) -> None:
        """agent 连上一个工具时问的。"""
        self.request("server/discover")
        self.request("tools/list")
        self.request("resources/list")

    def look(self) -> None:
        """打开扫描的页时读的那些。"""
        self.read(OUTBOX)
        self.read("summary")
        self.read("permissions")
        for page in ("overview", "cleaned"):
            self.read("page/" + page)

    def item(self, kind: str, title: str = "") -> dict:
        for it in self.outbox:
            if it["kind"] == kind and title in it["title"]:
                return it
        raise Failed(f"outbox 里没有 {kind}（{title}）；有 {[(i['kind'], i['title']) for i in self.outbox]}")

    def click(self, event: str, label: str = "", *, item: Optional[dict] = None, page: Optional[str] = None,
              choose: Optional[Dict[str, str]] = None, note: str = "", progress: bool = False) -> Any:
        """用户在卡片（outbox 的一件）或基础页上点了一个按钮。`progress`：像 agent 那样带上 progressToken，
        记下答复之前的进度通知（工具协议 §5）。"""
        sid = surface_id(item["card"]) if item is not None else page
        if sid is None or sid not in self.surfaces:
            raise Failed("没有这张卡片")
        surface = self.surfaces[sid]
        for label_part, value in (choose or {}).items():
            surface.choose(label_part, value)
        cid, ctx = surface.button(event, label)
        args = resolve(ctx, surface.data)
        ua = {"surfaceId": sid, "componentId": cid, "at": self.clock.astimezone(LOCAL).isoformat(timespec="seconds")}
        res = self.request("tools/call", {"name": event, "arguments": args}, user_action=ua, note=note,
                           progress_token=f"{sid}/{cid}" if progress else None)
        card = ((res or {}).get("structuredContent") or {}).get("card")
        if card and page is None:
            surface.apply(card)   # agent 用答复的卡片换掉原来那张；基础页不画答复的卡片，重新读那一页
        return res

    def call(self, tool: str, args: Optional[dict] = None, *, user_action: Optional[dict] = None, note: str = "") -> Any:
        """对话里模型调的工具（没有点按，除非给了 user_action）：答一张新卡片的就画上。"""
        res = self.request("tools/call", {"name": tool, "arguments": args or {}}, user_action=user_action, note=note)
        card = ((res or {}).get("structuredContent") or {}).get("card")
        if card:
            self.surfaces.setdefault(surface_id(card), Surface()).apply(card)
        return res

    def scanning(self) -> bool:
        """还有查这个假目录的 luoke-scan 在跑（报告写完以后它还要放锁、退出）。"""
        ps = subprocess.run(["/bin/ps", "-axww", "-o", "command="], stdout=subprocess.PIPE, text=True).stdout
        return any(self.r.fx.root in line and " scan " in line for line in ps.splitlines())

    def wait_round(self, clock: datetime.datetime, timeout: float = 120) -> None:
        """scan_now 另起了一轮（自己一个进程）：等到这台假 Mac 上一轮的报告是 clock 那一轮的。只看命令行的 status，不记进 golden。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            code, out, _ = self.r.exec(["status", "--data", self.r.fx.data, "--json"])
            if code == 0 and json.loads(out).get("startedAt") == iso(clock) and not self.scanning():
                return
            time.sleep(0.3)
        raise Failed(f"等了 {timeout} 秒，{iso(clock)} 那一轮还没查完")
