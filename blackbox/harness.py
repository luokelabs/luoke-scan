"""跑一个场景：在新建的临时目录里造假目录，一步一步起被测的 luoke-scan，把每一步的输出换成占位后记下来。"""
from __future__ import annotations

import copy
import datetime
import getpass
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

from fx import Fx, iso, xattr_names
from hub import Hub

TZ = "Asia/Shanghai"   # 卡片、文字里的「10月20日 20:00」按本机时区写；跑的时候固定成这个
TIMEOUT = 300
PROTOCOL = "2026-07-28"                 # 工具协议里 MCP 的版本
USER_ACTION = "ai.luoke/user-action"    # 用户点过才带的那一段
# 每一步前后比一遍的地方（假目录根下的）；扫描自己的数据、假扫描器、远程仓库、git 的内部不看。
# macOS 自己记的扩展属性（来源、Spotlight 的）：有没有要看是谁写的、哪台 Mac，不算。
OS_XATTRS = {"com.apple.provenance", "com.apple.lastuseddate#PS", "com.apple.macl"}
WATCHED = ["home", "tmp", "Trash", "SystemLibrary", "Shared", "usr-local", "opt-homebrew", "etc", "receipts"]


class Failed(Exception):
    pass


# 被测程序自己的版本号（run.py 起头问一次 `luoke-scan version`）：golden 里写成 $VERSION，升版本号不用重录。
TOOL_VERSION: Optional[str] = None


class Case:
    def __init__(self, name: str, about: str, run: Callable[["Run"], None], quiet: bool):
        self.name, self.about, self.run, self.quiet = name, about, run, quiet


CASES: Dict[str, Case] = {}


def case(name: str, about: str, *, quiet: bool = True) -> Callable[[Callable[["Run"], None]], Callable[["Run"], None]]:
    """登记一个场景。name 是 golden 下的相对路径（不带 .json），about 一句话说它测什么。
    quiet：假目录从一台没毛病的 Mac 起（fx.quiet_fakes）；False 用单元测试那份标准的假答案（有进程、FileVault 关着…）。"""
    def deco(f: Callable[["Run"], None]) -> Callable[["Run"], None]:
        if name in CASES:
            raise ValueError(f"场景重名：{name}")
        CASES[name] = Case(name, about, f, quiet)
        return f
    return deco


class Run:
    """一个场景的一次运行。fx 是它的假目录；每调一次 luoke-scan 记一步。"""

    def __init__(self, c: Case, binary: str, keep: bool):
        self.case, self.binary, self.keep = c, binary, keep
        self.work = os.path.realpath(tempfile.mkdtemp(prefix="luoke-scan-bb-"))
        self.fx = Fx(os.path.join(self.work, "fx"), quiet=c.quiet)
        # 被测的程序看到的家目录（HOME）：一个空的、不是假家目录的地方。假目录模式不该碰它，碰了也碰不到真的。
        self.fake_real_home = os.path.join(self.work, "not-home")
        os.makedirs(self.fake_real_home)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("LUOKE_")}
        self.env.update(TZ=TZ, HOME=self.fake_real_home)
        self.steps: List[Dict[str, Any]] = []
        self.fakes_seen = copy.deepcopy(self.fx.fakes)
        self.commands_seen = 0
        self.rid = 0
        self.hub: Optional[Hub] = None

    def start_hub(self, tasks: Dict[str, str], answers: Optional[Dict[str, Any]] = None) -> Hub:
        """起一个假主控（hub.Hub），之后的命令都带着 LUOKE_HUB_SOCKET 指向它；它收到的请求记进那一步的 "hub"。"""
        self.hub = Hub(tasks, answers)
        self.env["LUOKE_HUB_SOCKET"] = self.hub.path
        return self.hub

    # 起程序

    def exec(self, args: List[str], stdin: Optional[str] = None) -> Tuple[int, str, str]:
        try:
            r = subprocess.run([self.binary, *args], env=self.env, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=TIMEOUT, cwd=self.work)
        except subprocess.TimeoutExpired:
            raise Failed(f"luoke-scan {' '.join(args)} {TIMEOUT} 秒没跑完")
        return r.returncode, r.stdout, r.stderr

    def run_step(self, args: List[str], stdin: Optional[str], step: Dict[str, Any]) -> Tuple[int, str, str]:
        """跑一次，前后各量一遍假目录：改了的文件记进 step["tree"]，这一次要跑的系统命令（假目录模式只记不跑）记进
        step["commands"]。假答案（fakes.json）在这之前改过的，先记一步 {"fakes": 改了的键}。"""
        self.fx.save()
        changed = {k: v for k, v in self.fx.fakes.items() if self.fakes_seen.get(k) != v}
        if changed:
            self.steps.append({"fakes": own_uid(copy.deepcopy(changed))})
            self.fakes_seen = copy.deepcopy(self.fx.fakes)
        before = tree(self.fx.root)
        code, out, err = self.exec(args, stdin)
        diff = tree_diff(before, tree(self.fx.root))
        if diff:
            step["tree"] = diff
        if self.hub:
            asked = self.hub.take()
            if asked:
                step["hub"] = asked
        log = os.path.join(self.fx.root, "commands.log")
        if os.path.exists(log):
            lines = open(log, encoding="utf-8").read().splitlines()
            if len(lines) > self.commands_seen:
                step["commands"] = [json.loads(x) for x in lines[self.commands_seen:]]
                self.commands_seen = len(lines)
        return code, out, err

    def cli(self, *args: str, stdin: Optional[str] = None, json_out: bool = False, note: str = "") -> Any:
        """跑一次 luoke-scan，记下退出码和输出（json_out：标准输出解成 JSON）。返回输出。"""
        step: Dict[str, Any] = {}
        code, out, err = self.run_step(list(args), stdin, step)
        step.update({"run": ["luoke-scan", *args], "exit": code})
        if note:
            step["note"] = note
        if stdin is not None:
            step["stdin"] = stdin
        value: Any = out
        if json_out and code == 0:
            try:
                value = json.loads(out)
            except ValueError:
                raise Failed(f"luoke-scan {' '.join(args)} 的输出不是 JSON：{out[:300]}")
            step["json"] = value
        else:
            step["stdout"] = out.splitlines()
        if err.strip():
            step["stderr"] = err.splitlines()
        self.steps.append(step)
        return value

    def update(self, *, force: bool = True) -> None:
        self.cli("update", "--data", self.fx.data, "--tool-dir", self.fx.tools, *(["--force"] if force else []))

    def scan(self, clock: datetime.datetime, *flags: str, note: str = "") -> Dict[str, Any]:
        """查一轮（假目录模式，时钟停在 clock），记下报告。"""
        r = self.cli("scan", "--fixture", self.fx.root, "--clock", iso(clock), "--json", *flags, json_out=True, note=note)
        if not isinstance(r, dict):
            raise Failed(f"scan 没出报告：{self.steps[-1]}")
        return r

    def mcp_raw(self, stdin: str, *, clock: datetime.datetime, note: str = "") -> Any:
        """原样发一段标准输入（坏的 JSON、通知、协议版本不对的……）：记下发了什么、退出码、答复。"""
        args = ["mcp", "--fixture", self.fx.root, "--clock", iso(clock)]
        step: Dict[str, Any] = {}
        code, out, err = self.run_step(args, stdin, step)
        step.update({"mcp-raw": stdin, "clock": iso(clock), "exit": code})
        if note:
            step["note"] = note
        reply = None
        if out.strip():
            try:
                reply = json.loads(out)
                step["reply"] = reply
            except ValueError:
                step["stdout"] = out.splitlines()
        if err.strip():
            step["stderr"] = err.splitlines()
        self.steps.append(step)
        return reply

    def mcp(self, method: str, params: Optional[Dict[str, Any]] = None, *, clock: datetime.datetime,
            user_action: Optional[Dict[str, Any]] = None, no_fda: bool = False, note: str = "",
            protocol: str = PROTOCOL, progress_token: Any = None) -> Any:
        """agent 的一个请求：`luoke-scan mcp --fixture … --clock …`，标准输入一条 JSON-RPC，标准输出是答复。
        记下方法、参数（不记每次都一样的 _meta）、点按、答复（资源里那段 JSON 文字解开）。返回 result。
        给了 `progress_token`：请求带上它，答复之前的进度通知（notifications/progress）一条条记在 `progress` 里。"""
        self.rid += 1
        meta: Dict[str, Any] = {"io.modelcontextprotocol/protocolVersion": protocol,
                                "io.modelcontextprotocol/clientInfo": {"name": "luoke-agent", "version": "blackbox"},
                                "io.modelcontextprotocol/clientCapabilities": {}}
        if user_action:
            meta[USER_ACTION] = user_action
        if progress_token is not None:
            meta["progressToken"] = progress_token
        req = {"jsonrpc": "2.0", "id": self.rid, "method": method, "params": {**(params or {}), "_meta": meta}}
        args = ["mcp", "--fixture", self.fx.root, "--clock", iso(clock)] + (["--no-full-disk-access"] if no_fda else [])
        step: Dict[str, Any] = {}
        code, out, err = self.run_step(args, json.dumps(req, ensure_ascii=False), step)
        step.update({"mcp": method, "clock": iso(clock), "exit": code})
        if params:
            step["params"] = params
        if user_action:
            step["user-action"] = user_action
        if no_fda:
            step["no-full-disk-access"] = True
        if note:
            step["note"] = note
        if progress_token is not None:
            step["progress-token"] = progress_token
            lines = out.strip().splitlines()
            notes = []
            for line in lines[:-1]:
                try:
                    n = json.loads(line)
                except ValueError:
                    raise Failed(f"mcp {method} 答复之前的一行不是 JSON：{line[:300]}")
                if "id" in n or n.get("method") != "notifications/progress":
                    raise Failed(f"mcp {method} 答复之前的一行不是进度通知：{line[:300]}")
                notes.append(n.get("params"))
            step["progress"] = notes
            out = lines[-1] if lines else ""
        reply: Any = None
        if out.strip():
            try:
                reply = json.loads(out)
            except ValueError:
                raise Failed(f"mcp {method} 答的不是 JSON：{out[:300]}")
            shown = copy.deepcopy(reply)
            for c in (shown.get("result") or {}).get("contents") or []:
                if c.get("mimeType") == "application/json" and isinstance(c.get("text"), str):
                    c["text"] = json.loads(c["text"])
            step["reply"] = shown
        if err.strip():
            step["stderr"] = err.splitlines()
        self.steps.append(step)
        if reply is None:
            return None
        if "error" in reply:
            return reply
        return reply.get("result")

    def note(self, text: str) -> None:
        """记一步不是跑程序的（假目录里改了什么）。"""
        self.steps.append({"do": text})

    def close(self) -> None:
        if self.hub:
            self.hub.close()
        if not self.keep:
            shutil.rmtree(self.work, ignore_errors=True)


# ---------------------------------------------------------------- 假目录的样子

def tree(root: str) -> Dict[str, str]:
    """WATCHED 下每一项：类型、大小、权限、修改时间（文件）、链接指向、扩展属性的名字。"""
    out: Dict[str, str] = {}
    for top in WATCHED:
        base = os.path.join(root, top)
        if not os.path.lexists(base):
            continue
        for d, dirs, files in os.walk(base):
            dirs[:] = sorted(x for x in dirs if x != ".git")
            for name in dirs + sorted(files):
                p = os.path.join(d, name)
                try:
                    st = os.lstat(p)
                except FileNotFoundError:
                    continue
                rel = os.path.relpath(p, root)
                xs = [x for x in xattr_names(p) if x not in OS_XATTRS]
                tail = (" xattr=" + ",".join(xs)) if xs else ""
                if os.path.islink(p):
                    out[rel] = f"link -> {os.readlink(p)}{tail}"
                elif os.path.isdir(p):
                    out[rel] = f"dir {oct(st.st_mode & 0o7777)}{tail}"
                else:
                    out[rel] = f"file {st.st_size} {oct(st.st_mode & 0o7777)} {int(st.st_mtime)}{tail}"
    return out


def tree_diff(a: Dict[str, str], b: Dict[str, str]) -> Dict[str, List[str]]:
    """排序按换成占位以后的名字（废纸篓里的随机前缀不算），每次都一样。"""
    def order(keys: Any) -> List[str]:
        return sorted(keys, key=lambda k: (TRASH_NAME.sub("", k), k))
    d: Dict[str, List[str]] = {}
    added = [f"{k}: {b[k]}" for k in order(set(b) - set(a))]
    removed = [f"{k}: {a[k]}" for k in order(set(a) - set(b))]
    changed = [f"{k}: {a[k]} => {b[k]}" for k in order(set(a) & set(b)) if a[k] != b[k]]
    for key, v in (("added", added), ("removed", removed), ("changed", changed)):
        if v:
            d[key] = v
    return d


# ---------------------------------------------------------------- 换成占位

def own_uid(v: Any) -> Any:
    """假进程表、键盘监听里跑的这个用户的 uid 写成 "$UID"（各台 Mac 不一样）。"""
    if isinstance(v, dict):
        return {k: ("$UID" if k == "uid" and x == os.getuid() else own_uid(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [own_uid(x) for x in v]
    if isinstance(v, str):
        return v.replace(f"gui/{os.getuid()}", "gui/$UID")
    return v


DROP = {"ruleSeconds", "startedWall"}   # 每次都不一样的：各规则用了几秒、真实的开始时间
MASK = {"inode": "$INODE", "device": "$DEVICE"}   # 清理记录里的文件身份：每次、每台 Mac 都不一样，只记有没有


def tidy(v: Any) -> Any:
    """报告里和机器、时间有关的拿掉；发现、没扫描的按内容排好（顺序不算约定）。"""
    if isinstance(v, dict):
        out = {k: (MASK[k] if k in MASK and isinstance(x, int) else tidy(x)) for k, x in v.items() if k not in DROP}
        if "findings" in out and isinstance(out["findings"], list) and "schema" in out:
            out["findings"] = sorted(out["findings"], key=lambda f: json.dumps(f, sort_keys=True, ensure_ascii=False))
        if "skipped" in out and isinstance(out["skipped"], list) and "schema" in out:
            out["skipped"] = sorted(out["skipped"], key=lambda s: json.dumps(s, sort_keys=True, ensure_ascii=False))
        return out
    if isinstance(v, list):
        return [tidy(x) for x in v]
    return v


def placeholders(r: Run) -> List[Tuple[str, str]]:
    spellings = {r.work}
    spellings |= {p[len("/private"):] for p in spellings if p.startswith("/private/")}
    pairs: List[Tuple[str, str]] = []
    for root in sorted(spellings, key=len, reverse=True):
        fx = os.path.join(root, "fx")
        pairs += [(os.path.join(fx, "home"), "~"), (os.path.join(fx, "tmp"), "$TMPDIR"), (fx, "$FIXTURE"), (root, "$WORK")]
    return pairs


# 由路径和随机数算出的 12 位编号（发现、方案、清理记录的 id）：按出现的先后换成 000000000001……
HASH = re.compile(r"(?<=[/-])[0-9a-f]{12}(?![0-9A-Za-z])")
TRUNCATED = re.compile(r"(?:/private)?/var/folders/[^\s\"\\]*?…")
# 移进假废纸篓时加的随机前缀
TRASH_NAME = re.compile(r"(?<=Trash/)[0-9A-Fa-f]{8}-")
# 用例里拼出来的假令牌（假进程的命令行参数会原样记进 golden）：照公开导出、出版泄漏检查的「令牌」规则写成 $FAKE_TOKEN，
# golden 里不留令牌样子的字面量，不然那两处检查会停在它上面。扫描报告本来就不写令牌的值，真写了也看得出来（报告里多了 $FAKE_TOKEN）
FAKE_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bglpat-[A-Za-z0-9_-]{20,}|\bhf_[A-Za-z0-9]{30,}"
                        r"|\bsk-ant-[A-Za-z0-9_-]{20,}")


def golden(r: Run) -> str:
    doc = {"case": r.case.name, "about": r.case.about, "steps": tidy(r.steps)}
    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True)
    text = text.replace(r.binary, "luoke-scan")   # 程序打印的自己的路径（建议的命令）
    for real, ph in placeholders(r):
        text = text.replace(real, ph)
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # 评测用例这些仓库里的文件
    for spelling in sorted({repo, repo[len("/private"):] if repo.startswith("/private/") else repo}, key=len, reverse=True):
        text = text.replace(spelling, "$REPO")
    text = text.replace(f"gui/{os.getuid()}", "gui/$UID")
    # 太长被截短的路径（给模型看的起名输入）：截下来的前半段落在系统临时目录的名字里，各台 Mac 不一样（长度一样）
    text = TRUNCATED.sub("$CUT…", text)
    if r.hub:
        text = text.replace(r.hub.path, "$HUB")
    if TOOL_VERSION:
        v = re.escape(TOOL_VERSION)
        text = re.sub(r'("version": )"' + v + '"', r'\1"$VERSION"', text)
        text = re.sub(r"luoke-scan([ /])" + v + r"(?![0-9.])", r"luoke-scan\1$VERSION", text)
    mapping: Dict[str, str] = {}
    text = HASH.sub(lambda m: mapping.setdefault(m.group(0), f"{len(mapping) + 1:012d}"), text)
    text = TRASH_NAME.sub("XXXXXXXX-", text)
    text = FAKE_TOKEN.sub("$FAKE_TOKEN", text)
    return text + "\n"


LEAKS = re.compile(r"/Users/|/private/var/folders|/var/folders|/private/tmp/|\$WORK")


def leaks(text: str) -> List[str]:
    """golden 里不该有的：真实的家目录、临时目录，跑的这台 Mac 的用户名（整个词）。"""
    found = set(LEAKS.findall(text))
    user = getpass.getuser()
    if len(user) > 2 and re.search(r"(?<![A-Za-z0-9])" + re.escape(user) + r"(?![A-Za-z0-9])", text):
        found.add("用户名 " + user)
    return sorted(found)
