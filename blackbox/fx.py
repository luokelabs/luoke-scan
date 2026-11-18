"""造假目录：从外面测扫描（blackbox/README.md）用的假用户目录，和它旁边的 fakes.json。

只用标准库，不依赖被测的程序：Swift 版、Go 版对着同一份假目录跑。目录的样子是扫描「假目录模式」（--fixture）的约定：

    <根>/home                 假的家目录（项目在 home/Projects）
    <根>/tmp                  本用户的临时目录
    <根>/tools                假的 clamscan、freshclam、sigtool、yara 和 XProtect.yara
    <根>/fakes.json           本机状态的假答案（进程、系统设置、签名、Spotlight、磁盘……）
    <根>/data                 扫描自己的数据（被测的程序建，这里不碰）
    <根>/SystemLibrary、receipts、Shared、usr-local、opt-homebrew、etc、usr-sbin、remotes、Trash
    <根>/backgroundtaskmanagement  「登录项与扩展」的记录（当 /private/var/db/com.apple.backgroundtaskmanagement）
"""
from __future__ import annotations

import copy
import ctypes
import ctypes.util
import datetime
import json
import os
import plistlib
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Union

UTC = datetime.timezone.utc
LOCAL = datetime.timezone(datetime.timedelta(hours=8), "CST")   # 跑的时候 TZ 是 Asia/Shanghai
T0 = datetime.datetime(2026, 10, 20, 12, 0, tzinfo=UTC)   # 假目录的「现在」
HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "tools")
MiB = 1 << 20


def days(n: float) -> datetime.datetime:
    """T0 之前 n 天（负数是之后）。"""
    return T0 - datetime.timedelta(days=n)


def iso(t: datetime.datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- 文件的时间、扩展属性

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


class _AttrList(ctypes.Structure):
    _fields_ = [("bitmapcount", ctypes.c_ushort), ("reserved", ctypes.c_uint16), ("commonattr", ctypes.c_uint32),
                ("volattr", ctypes.c_uint32), ("dirattr", ctypes.c_uint32), ("fileattr", ctypes.c_uint32),
                ("forkattr", ctypes.c_uint32)]


class _Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


_CRTIME, _ADDEDTIME, _NOFOLLOW = 0x00000200, 0x10000000, 0x00000001


def _check(rc: int, path: str) -> None:
    if rc != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e), path)


def set_times(path: str, t: datetime.datetime, *, born: Optional[datetime.datetime] = None,
              added: Optional[datetime.datetime] = None) -> None:
    """修改时间设成 t；创建时间、「添加日期」（来到这个文件夹的时间）默认也是 t。不跟着链接走。"""
    b, a = int((born or t).timestamp()), int((added or born or t).timestamp())
    al = _AttrList(5, 0, _CRTIME | _ADDEDTIME, 0, 0, 0, 0)
    buf = (_Timespec * 2)(_Timespec(b, 0), _Timespec(a, 0))
    _check(_libc.setattrlist(path.encode(), ctypes.byref(al), ctypes.byref(buf), ctypes.sizeof(buf), _NOFOLLOW), path)
    ts = int(t.timestamp())
    os.utime(path, (ts, ts), follow_symlinks=False)


def set_xattr(path: str, name: str, value: bytes) -> None:
    _check(_libc.setxattr(path.encode(), name.encode(), value, len(value), 0, _NOFOLLOW), path)


def xattr_names(path: str) -> List[str]:
    """扩展属性的名字（不跟着链接走）。"""
    n = _libc.listxattr(path.encode(), None, 0, _NOFOLLOW)
    if n <= 0:
        return []
    buf = ctypes.create_string_buffer(n)
    n = _libc.listxattr(path.encode(), buf, n, _NOFOLLOW)
    return sorted(x.decode(errors="replace") for x in buf.raw[:max(n, 0)].split(b"\0") if x)


# ---------------------------------------------------------------- 本机状态的假答案（fakes.json）

def standard_fakes(home: str) -> Dict[str, Any]:
    """和扫描的 Fixture.Fakes.standard 一样的一份：什么都没共享、没人自动登录、没加根证书、FileVault 关着、
    一个更新没装、开机 79 天；进程表是下面 standard_processes 的。"""
    return {
        "version": 1,
        "processes": standard_processes(home),
        "launchdPIDs": [300],
        "commands": [
            {"tool": "/usr/bin/defaults", "args": ["autoLoginUser"], "status": 1, "output": ""},
            {"tool": "/usr/bin/defaults", "args": ["GuestEnabled"], "status": 0, "output": "0\n"},
            {"tool": "/usr/bin/defaults", "args": ["DiscoverableMode"], "status": 0, "output": "Contacts Only\n"},
            {"tool": "/bin/launchctl", "args": [], "status": 0, "output": "disabled services = {\n\t\"com.openssh.sshd\" => disabled\n}\n"},
            {"tool": "/usr/bin/security", "args": [], "status": 1, "output": "SecTrustSettings: No Trust Settings were found.\n"},
            {"tool": "/usr/bin/fdesetup", "args": [], "status": 0, "output": "FileVault is Off.\n"},
            {"tool": "/usr/libexec/ApplicationFirewall/socketfilterfw", "args": [], "status": 0, "output": "Firewall is enabled. (State = 1)\n"},
            {"tool": "/usr/bin/csrutil", "args": [], "status": 0, "output": "System Integrity Protection status: enabled.\n"},
            {"tool": "/usr/sbin/spctl", "args": [], "status": -1, "output": ""},
            {"tool": "/bin/sh", "args": [], "status": 0, "output": "sysadminctl[1:2] screenLock delay is immediate\n"},
        ],
        "otherCommands": {"status": 0, "output": "1\n"},
        "bootTime": iso(days(79)),
        "pendingUpdates": 1,
        "xprotectUpdated": iso(days(3)),
        "signatures": [{"pathContains": "unsigned", "signature": "unsigned"}],
        "otherSignature": "developer:FIXTURE000",
        "eventTaps": [],
        "snapshots": [],
        "appleSilicon": True,
        "running": [],
        "commandLines": [],
        "attachedImages": [],
        "crontab": "",
        "installedCommands": [],
        "volume": None,
        "staleFiles": [],
        "downloaded": [],
        "appsAdded": {},
        "codesign": {},
        "appTrust": {},
        "onBattery": False,
        "lowPower": False,
        "memoryPressure": 1,
        # 运行状况（luoke-scan#126）：一台运行正常的台式机。cpu 是两次读数之间各进程的处理器秒数（按 pid），
        # footprint 各进程占的内存；pressure 1 正常、2 警告、4 严重；battery null 是没有电池；thermal 是两次读到的发热档位。
        "vitals": {"cpu": {}, "sampleSeconds": 3, "footprint": {}, "memTotal": 16 * 1024 ** 3, "pressure": 1, "swap": 0,
                   "battery": None, "batteryUnknown": False, "thermal": [0, 0]},
    }


def quiet_fakes(home: str) -> Dict[str, Any]:
    """一台没毛病的 Mac：只开着一个应用，FileVault 开着，Gatekeeper 开着，没有等着装的更新。规则的场景从这里起，
    结果里只有那条规则要看的东西。"""
    f = standard_fakes(home)
    # 进程表不能是空的（空的算读不到）：只有一个开着的应用。
    f["processes"] = [p for p in f["processes"] if p["pid"] == 400]
    f["launchdPIDs"], f["pendingUpdates"] = [], 0
    for c in f["commands"]:
        if c["tool"] == "/usr/bin/fdesetup":
            c["output"] = "FileVault is On.\n"
        if c["tool"] == "/usr/sbin/spctl":
            c["status"], c["output"] = 0, "assessments enabled\n"
    return f


BROWSER_HELPER = "Applications/Browser.app/Contents/Frameworks/Helper (Renderer).app/Contents/MacOS/Helper"
# 有意脱离父进程的 gpg-agent：在假目录的 /opt/homebrew 里（Fx 建出来），不指跑测试那台机器上装的。
GPG_AGENT = "opt-homebrew/bin/gpg-agent"
# 系统自带、每台 Mac 都有的程序在这些地方。进程表里本用户别的程序都要在假目录里：指机器上装的第三方程序
# （Homebrew 的、/usr/local 里的），没装它的机器上就多报一条「程序已经被删掉了」，结果随机器变。
SYSTEM_PROGRAMS = ("/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/", "/Applications/Safari.app/")


def standard_processes(home: str) -> List[Dict[str, Any]]:
    """程序没了的一个、一个父进程下 25 个 lsof、老的孤儿、launchd 起的、一个应用；本来就挂在 1 下面的系统服务，
    有意脱离父进程的 gpg-agent。"""
    me = os.getuid()

    def p(pid: int, ppid: int, path: str, started: datetime.datetime, uid: int = me) -> Dict[str, Any]:
        return {"pid": pid, "ppid": ppid, "uid": uid, "path": path, "started": iso(started)}

    out = [p(100, 1, home + "/Applications/Gone.app/Contents/MacOS/gone", days(2)),
           p(200, 1, "/usr/bin/log", days(1)),
           p(300, 1, "/usr/bin/log", days(1)),
           p(400, 1, "/Applications/Safari.app/Contents/MacOS/Safari", days(1)),
           p(500, 1, "/usr/bin/caffeinate", T0 - datetime.timedelta(minutes=10)),
           p(600, 1, "/usr/sbin/someone-else", days(9), uid=0),
           p(1000, 50, "/bin/sh", days(1)),
           p(700, 1, "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent", days(5)),
           p(701, 1, "/System/Library/ExtensionKit/Extensions/WallpaperImageExtension.appex/Contents/MacOS/WallpaperImageExtension", days(5)),
           p(702, 1, os.path.join(os.path.dirname(home), GPG_AGENT), days(20)),
           p(703, 1, "/usr/bin/tail", days(6))]
    out += [p(2000 + i, 1999, home + "/" + BROWSER_HELPER, T0) for i in range(30)]
    out += [p(1001 + i, 1000, "/usr/sbin/lsof", T0) for i in range(25)]
    return out


# ---------------------------------------------------------------- 假目录

GIT_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}

Data = Union[bytes, str, None]


class Fx:
    """一个假目录。路径写法：`~/…` 在假家目录下，`$TMPDIR/…` 在假临时目录下，别的相对于根。"""

    def __init__(self, root: str, *, quiet: bool = False):
        self.root = root
        self.home = os.path.join(root, "home")
        self.tmp = os.path.join(root, "tmp")
        self.tools = os.path.join(root, "tools")
        self.data = os.path.join(root, "data")
        self.fakes = quiet_fakes(self.home) if quiet else standard_fakes(self.home)
        for d in (self.home, self.tmp, os.path.join(self.home, "Projects")):
            os.makedirs(d, exist_ok=True)
        os.makedirs(self.tools, exist_ok=True)
        for name in os.listdir(TOOLS):
            shutil.copy2(os.path.join(TOOLS, name), os.path.join(self.tools, name))
        if not quiet:   # 标准进程表里的 gpg-agent 在跑，它的程序在（不然成了「程序被删了」）
            self.file(GPG_AGENT, "#!/bin/sh\nexit 0\n", mode=0o755, at=days(30))

    # 路径

    def p(self, rel: str) -> str:
        if rel == "~" or rel.startswith("~/"):
            return os.path.join(self.home, rel[2:]) if rel != "~" else self.home
        if rel == "$TMPDIR" or rel.startswith("$TMPDIR/"):
            return os.path.join(self.tmp, rel[len("$TMPDIR/"):]) if rel != "$TMPDIR" else self.tmp
        return rel if os.path.isabs(rel) else os.path.join(self.root, rel)

    # 文件

    def file(self, rel: str, data: Data = None, *, size: int = 0, fill: int = 0, at: Optional[datetime.datetime] = None,
             born: Optional[datetime.datetime] = None, added: Optional[datetime.datetime] = None,
             mode: Optional[int] = None) -> str:
        """写一个文件：data（字节或文字），或者 size 个 fill 字节。at 是修改时间（默认 T0）。"""
        path = self.p(rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        body = data.encode() if isinstance(data, str) else data if data is not None else bytes([fill]) * size
        with open(path, "wb") as f:
            f.write(body)
        if mode is not None:
            os.chmod(path, mode)
        set_times(path, at or T0, born=born, added=added)
        return path

    def dir(self, rel: str, *, at: Optional[datetime.datetime] = None, mode: Optional[int] = None) -> str:
        path = self.p(rel)
        os.makedirs(path, exist_ok=True)
        if mode is not None:
            os.chmod(path, mode)
        if at:
            set_times(path, at)
        return path

    def plist(self, rel: str, obj: Any, *, at: Optional[datetime.datetime] = None, binary: bool = False) -> str:
        fmt = plistlib.FMT_BINARY if binary else plistlib.FMT_XML
        return self.file(rel, plistlib.dumps(obj, fmt=fmt), at=at)

    def json(self, rel: str, obj: Any, *, at: Optional[datetime.datetime] = None) -> str:
        return self.file(rel, json.dumps(obj, ensure_ascii=False, indent=2), at=at)

    def link(self, rel: str, target: str) -> str:
        path = self.p(rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(target, path)
        return path

    def touch(self, rel: str, at: datetime.datetime) -> None:
        set_times(self.p(rel), at)

    def age(self, rel: str, at: datetime.datetime) -> None:
        """rel 和它下面所有东西（.git 里的除外）的时间都设成 at，从最深的开始。"""
        top = self.p(rel)
        paths: List[str] = []
        for d, dirs, files in os.walk(top):
            if ".git" in dirs:
                dirs.remove(".git")
            paths += [os.path.join(d, n) for n in dirs + files]
        for path in sorted(paths, key=lambda s: s.count("/"), reverse=True):
            set_times(path, at)
        set_times(top, at)

    def remove(self, rel: str) -> None:
        path = self.p(rel)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    def quarantine(self, rel: str, agent: str = "Safari") -> None:
        """浏览器下载时打的 Gatekeeper 标记。"""
        set_xattr(self.p(rel), "com.apple.quarantine", f"0083;00000000;{agent};".encode())

    def adhoc_sign(self, rel: str) -> None:
        """临时签名（codesign -s -）：有签名、不认得是谁的。时间不变。"""
        path = self.p(rel)
        st = os.lstat(path)
        subprocess.run(["/usr/bin/codesign", "-s", "-", "-f", path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.utime(path, (st.st_atime, st.st_mtime), follow_symlinks=False)

    def app(self, rel: str, bundle_id: str, name: str, version: str = "1.0", *, at: Optional[datetime.datetime] = None,
            executable: bool = True, extra: Optional[Dict[str, Any]] = None) -> str:
        """一个最简的 .app：Info.plist，加一个能跑的程序（Contents/MacOS/<name>）。"""
        info = {"CFBundleIdentifier": bundle_id, "CFBundleName": name, "CFBundleShortVersionString": version,
                "CFBundleExecutable": name}
        info.update(extra or {})
        self.plist(rel + "/Contents/Info.plist", info, at=at)
        if executable:
            self.file(rel + f"/Contents/MacOS/{name}", "#!/bin/sh\nexit 0\n", at=at, mode=0o755)
        return self.p(rel)

    # git

    def git(self, rel: str, *args: str, at: datetime.datetime) -> None:
        stamp = f"{int(at.timestamp())} +0000"
        env = dict(GIT_ENV, GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp, HOME=self.root)
        r = subprocess.run(["/usr/bin/git", "-C", self.p(rel), *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} 在 {rel}：{r.stderr.strip()}")

    def repo(self, rel: str, *, remote: bool, at: datetime.datetime, ignore: Iterable[str] = ()) -> str:
        """一个仓库，main 上一个提交；remote 时建一个裸仓库当 origin 并推上去。"""
        self.file(rel + "/README.md", size=2048, at=at)
        ignore = list(ignore)
        if ignore:
            self.file(rel + "/.gitignore", "\n".join(ignore) + "\n", at=at)
        self.git(rel, "init", "-q", "-b", "main", at=at)
        self.git(rel, "add", "-A", at=at)
        self.git(rel, "commit", "-q", "-m", "init", at=at)
        if remote:
            bare = os.path.join(self.root, "remotes", os.path.basename(rel.rstrip("/")) + ".git")
            n = 1
            while os.path.exists(bare):
                n += 1
                bare = os.path.join(self.root, "remotes", f"{os.path.basename(rel.rstrip('/'))}-{n}.git")
            os.makedirs(bare)
            self.git(bare, "init", "-q", "--bare", at=at)
            self.git(rel, "remote", "add", "origin", bare, at=at)
            self.git(rel, "push", "-q", "origin", "main", at=at)
            self.git(rel, "fetch", "-q", "origin", at=at)
        return self.p(rel)

    def commit(self, rel: str, message: str, *, at: datetime.datetime) -> None:
        self.git(rel, "add", "-A", at=at)
        self.git(rel, "commit", "-q", "-m", message, at=at)

    # TCC

    TCC = "~/Library/Application Support/com.apple.TCC/TCC.db"

    def tcc(self, rows: Iterable[tuple]) -> str:
        """TCC 的授权表：(service, client, client_type, auth_value)。"""
        path = self.p(self.TCC)
        os.makedirs(os.path.dirname(path), exist_ok=True)

        def q(v: Any) -> str:
            return str(v) if isinstance(v, int) else "'" + str(v).replace("'", "''") + "'"
        sql = "CREATE TABLE IF NOT EXISTS access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER);\n"
        sql += "".join(f"INSERT INTO access VALUES ({', '.join(q(v) for v in r)});\n" for r in rows)
        subprocess.run(["/usr/bin/sqlite3", path, sql], check=True)
        return path

    BTM_USER = "0A1B2C3D-0000-4000-8000-00000000ABCD"   # 假目录里当本用户的 generated UID

    def btm(self, items: Iterable[Dict[str, Any]], *, version: int = 16) -> str:
        """「登录项与扩展」的记录：backgroundtaskmanagement/BackgroundItems-v<version>.btm，NSKeyedArchiver 存的二进制
        属性列表（Storage → itemsByUserIdentifier → ItemRecord）。每项：name、identifier、container、url、bundleIdentifier、
        associatedBundleIdentifiers（列表）、type、disposition，可选 user（默认 BTM_USER）。"""
        objects: List[Any] = ["$null"]

        def add(o: Any) -> plistlib.UID:
            objects.append(o)
            return plistlib.UID(len(objects) - 1)

        classes: Dict[str, plistlib.UID] = {}

        def cls(name: str, *supers: str) -> plistlib.UID:
            if name not in classes:
                classes[name] = add({"$classname": name, "$classes": [name, *supers, "NSObject"]})
            return classes[name]

        null = plistlib.UID(0)
        by_user: Dict[str, List[plistlib.UID]] = {}
        for it in items:
            rec: Dict[str, Any] = {"$class": cls("ItemRecord"), "type": it["type"], "disposition": it["disposition"],
                                   "generation": 1}
            for key in ("name", "identifier", "container", "bundleIdentifier"):
                rec[key] = add(it[key]) if it.get(key) else null
            if it.get("url"):
                rec["url"] = add({"$class": cls("NSURL"), "NS.base": null, "NS.relative": add(it["url"])})
            else:
                rec["url"] = null
            ids = it.get("associatedBundleIdentifiers")
            rec["associatedBundleIdentifiers"] = add({"$class": cls("NSArray"), "NS.objects": [add(x) for x in ids]}) if ids else null
            by_user.setdefault(it.get("user", self.BTM_USER), []).append(add(rec))
        users = add({"$class": cls("NSMutableDictionary", "NSDictionary"),
                     "NS.keys": [add(u) for u in by_user],
                     "NS.objects": [add({"$class": cls("NSMutableArray", "NSArray"), "NS.objects": v}) for v in by_user.values()]})
        store = add({"$class": cls("Storage"), "itemsByUserIdentifier": users, "mdmPayloadsByIdentifier": null})
        archive = {"$version": 100000, "$archiver": "NSKeyedArchiver", "$top": {"store": store, "version": add(version)},
                   "$objects": objects}
        return self.file(f"backgroundtaskmanagement/BackgroundItems-v{version}.btm", plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))

    # 本机状态

    def fake(self, key: str, value: Any) -> None:
        if key not in self.fakes:
            raise KeyError(f"fakes.json 没有 {key}")
        self.fakes[key] = value

    def command(self, tool: str, output: str, *, args: Iterable[str] = (), status: int = 0) -> None:
        """改一条系统命令的答复（插在最前面，先于默认的那些）。"""
        self.fakes["commands"].insert(0, {"tool": tool, "args": list(args), "status": status, "output": output})

    def save(self) -> None:
        me = os.getuid()
        # 假目录的根，和扫描拿到的那种写法（/private/var/… 去掉 /private）：两种都在假目录里
        roots = (self.root + "/", self.root[len("/private"):] + "/") if self.root.startswith("/private/") else (self.root + "/",)
        for p in self.fakes["processes"]:
            path = p["path"]
            if p["uid"] == me and path and not path.startswith(roots) and not path.startswith(SYSTEM_PROGRAMS):
                raise ValueError(f"假进程表里的 {path} 不在假目录里，也不是系统自带的：结果会随机器上装没装它变")
        with open(os.path.join(self.root, "fakes.json"), "w", encoding="utf-8") as f:
            json.dump(self.fakes, f, ensure_ascii=False, indent=2)

    # 假的扫描器

    def tool_flag(self, name: str, text: str = "") -> None:
        """假 freshclam 看的控制文件（fail-next、bad-next、same-next、next-version、db-date）。"""
        with open(os.path.join(self.tools, name), "w") as f:
            f.write(text)

    def clear_tool_flag(self, name: str) -> None:
        p = os.path.join(self.tools, name)
        if os.path.exists(p):
            os.remove(p)


def copy_fakes(f: Dict[str, Any]) -> Dict[str, Any]:
    return copy.deepcopy(f)
