"""系统这一组规则：进程（process）、看键盘的程序（keyboard）、对外露出的（exposure）、安全设置（posture）、病毒扫描（malware）。

进程表、launchd 的任务、系统命令的答复、开机时间、等着装的更新、XProtect 的日期、键盘监听都是 fakes.json 里的假答案
（r.fx.fake、r.fx.command）；SSH 钥匙、下载来的文件、后台任务的程序是假目录里的文件。病毒库由假的 freshclam 下，
它怎么答看 tools/ 里的控制文件（fail-next、bad-next、same-next、next-version、db-date）。

每个场景只摆它要看的东西，从一台没毛病的 Mac 起（quiet_fakes）：结果里只有那条规则的发现。
"""
from __future__ import annotations

import base64
import datetime
import os
from typing import Any, Dict, List, Optional

from fx import MiB, T0, Fx, days, iso
from harness import Run, case

ME = os.getuid()


def hours(n: float) -> datetime.datetime:
    """T0 之前 n 小时。"""
    return T0 - datetime.timedelta(hours=n)


def after(n: float) -> datetime.datetime:
    """T0 之后 n 天。"""
    return T0 + datetime.timedelta(days=n)


def prog(fx: Fx, rel: str) -> str:
    """假目录里一个在的程序（一个小脚本），返回它的绝对路径。"""
    return fx.file(rel, "#!/bin/sh\nexit 0\n", mode=0o755, at=days(30))


# ================================================================ 进程（process）

def proc(pid: int, ppid: int, path: str, started: datetime.datetime, uid: int = ME) -> Dict[str, Any]:
    return {"pid": pid, "ppid": ppid, "uid": uid, "path": path, "started": iso(started)}


def procs(r: Run, *ps: Dict[str, Any]) -> None:
    """进程表：没毛病的那台 Mac 本来就有的（开着的 Safari），再加上这些。"""
    r.fx.fake("processes", r.fx.fakes["processes"] + list(ps))


@case("rules/process/deleted-one", "一个进程的程序已经被删掉了还在跑：报一条；程序还在的、别的用户的、读不到路径的不报")
def process_deleted_one(r: Run) -> None:
    fx = r.fx
    here = prog(fx, "~/Applications/Here.app/Contents/MacOS/here")
    procs(r,
          proc(4100, 50, fx.p("~/Applications/Gone.app/Contents/MacOS/gone"), days(2)),
          proc(4101, 50, here, days(2)),
          proc(4102, 50, "/opt/io-example/gone-daemon", days(2), uid=0),   # 别的用户的：不看
          proc(4103, 50, "", days(2)))                                       # 读不到路径的
    r.update()
    r.scan(T0)


@case("rules/process/deleted-many", "同一个被删掉的程序跑着 25 个：合成一条，进程号只列最早起的 20 个；另一个被删的程序单独一条")
def process_deleted_many(r: Run) -> None:
    fx = r.fx
    helper = fx.p("~/Applications/Old.app/Contents/Frameworks/Old Helper.app/Contents/MacOS/Old Helper")
    # 起的时间倒着排：最早起的是进程号最大的那几个。
    ps = [proc(5000 + i, 4999, helper, hours(5 + i)) for i in range(25)]
    ps.append(proc(4999, 1, fx.p("~/Applications/Old.app/Contents/MacOS/Old"), days(3)))   # 应用本身：父进程是 1 也不算孤儿
    procs(r, *ps)
    r.update()
    r.scan(T0)


@case("rules/process/pile-up", "同一个父进程下堆了 20 个 lsof（正好到门槛）：报；另一个父进程（不在进程表里）下的 22 个再报一条，父进程写「?」")
def process_pile_up(r: Run) -> None:
    fx = r.fx
    poller = prog(fx, "~/.local/bin/status-poller")
    ps = [proc(6000, 50, poller, days(1))]
    ps += [proc(6001 + i, 6000, "/usr/sbin/lsof", T0) for i in range(20)]
    ps += [proc(6101 + i, 6100, "/usr/sbin/lsof", T0) for i in range(22)]   # 6100 不在进程表里
    procs(r, *ps)
    r.update()
    r.scan(T0)


@case("rules/process/pile-up-near-miss", "不算堆积的：差一个到门槛（19 个）、应用里的辅助进程 30 个、两种程序各 10 个、父进程是 1 的 25 个刚起的")
def process_pile_up_near_miss(r: Run) -> None:
    fx = r.fx
    runner = prog(fx, "~/.local/bin/runner")
    helper = prog(fx, "~/Applications/Browser.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper")
    ps = [proc(7000, 50, runner, days(1))]
    ps += [proc(7001 + i, 7000, "/usr/sbin/lsof", T0) for i in range(19)]
    ps += [proc(7100 + i, 7000, helper, T0) for i in range(30)]
    ps += [proc(7200 + i, 7000, "/usr/bin/true" if i % 2 else "/usr/bin/log", T0) for i in range(20)]
    ps += [proc(7300 + i, 1, "/usr/bin/caffeinate", T0) for i in range(25)]
    procs(r, *ps)
    r.update()
    r.scan(T0)


@case("rules/process/orphans", "父进程是 1、不是 launchd 的任务、跑了 6 小时以上的：合成一条，按跑得最久排；正好 6 小时的也算")
def process_orphans(r: Run) -> None:
    fx = r.fx
    watcher = prog(fx, "~/.local/bin/file-watcher")
    devserver = prog(fx, "~/.local/share/io.example/devserver")
    procs(r,
          proc(8001, 1, watcher, days(3)),
          proc(8002, 1, "/usr/bin/tail", days(6)),
          proc(8003, 1, devserver, hours(6)))
    r.update()
    r.scan(T0)


@case("rules/process/orphan-near-miss", "父进程是 1 但不算孤儿的：launchd 的任务、差一分钟到 6 小时、系统的服务、XPC 服务、扩展、应用、故意独立的守护进程、别的用户的")
def process_orphan_near_miss(r: Run) -> None:
    fx = r.fx
    job = prog(fx, "~/.local/bin/sync-job")
    young = prog(fx, "~/.local/bin/young")
    xpc = prog(fx, "~/.local/lib/Kit.framework/XPCServices/io.example.svc.xpc/Contents/MacOS/io.example.svc")
    appex = prog(fx, "~/Library/ExtensionKit/Extensions/io.example.ext.appex/Contents/MacOS/io.example.ext")
    app = prog(fx, "~/Applications/Menu.app/Contents/MacOS/Menu")
    gpg = prog(fx, "~/.local/bin/gpg-agent")
    tmux = prog(fx, "~/.local/bin/tmux")
    procs(r,
          proc(8101, 1, job, days(2)),
          proc(8102, 1, young, hours(6) + datetime.timedelta(minutes=1)),
          proc(8103, 1, "/usr/libexec/xpcproxy", days(4)),
          proc(8104, 1, "/usr/sbin/cfprefsd", days(4)),
          proc(8105, 1, "/sbin/launchd", days(4)),
          proc(8106, 1, "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock", days(4)),
          proc(8107, 1, xpc, days(4)),
          proc(8108, 1, appex, days(4)),
          proc(8109, 1, app, days(4)),
          proc(8110, 1, gpg, days(20)),
          proc(8111, 1, tmux, days(20)),
          proc(8112, 1, "/usr/bin/tail", days(9), uid=0))
    r.fx.fake("launchdPIDs", [8101])
    r.update()
    r.scan(T0)


@case("rules/process/orphans-many", "12 个孤儿：还是一条，进程号全列，「跑得最久的」只列前 10 个")
def process_orphans_many(r: Run) -> None:
    fx = r.fx
    ps = []
    for i in range(12):
        ps.append(proc(8200 + i, 1, prog(fx, f"~/.local/bin/worker-{i:02d}"), days(13 - i)))
    procs(r, *ps)
    r.update()
    r.scan(T0)


@case("rules/process/no-launchctl", "launchctl 没答复：不查孤儿，报一条「这一轮没查孤儿进程」；被删掉的程序照报")
def process_no_launchctl(r: Run) -> None:
    fx = r.fx
    procs(r,
          proc(8301, 1, prog(fx, "~/.local/bin/file-watcher"), days(3)),   # 有 launchctl 的话是孤儿
          proc(8302, 50, fx.p("~/bin/removed-tool"), days(1)))
    r.fx.fake("launchdPIDs", None)
    r.update()
    r.scan(T0)


def with_env(p: Dict[str, Any], env: List[str]) -> Dict[str, Any]:
    """进程启动时的环境变量（KERN_PROCARGS2 里 argv 后面那段）；不带的是读不到。"""
    p["environment"] = env
    return p


@case("rules/process/dyld-insert", "启动时带着 DYLD_INSERT_LIBRARIES 的进程：一个库一条，带着它的进程合在一起；没人担保的高、"
      "有开发者签名的中；苹果自己的库（系统位置的、Xcode 的）、别的变量、别的用户的、读不到环境变量的不报")
def process_dyld_insert(r: Run) -> None:
    fx = r.fx
    shell, tool = prog(fx, "~/.local/bin/shell"), prog(fx, "~/.local/bin/tool")
    hook = fx.file("~/.cache/io.example/hook.dylib", "not a real library\n", at=days(3))
    proxy = fx.file("~/.local/lib/libproxy.dylib", "not a real library\n", at=days(30))
    xcode = fx.file("~/Applications/Xcode.app/Contents/Developer/usr/lib/libMainThreadChecker.dylib", "not a real library\n",
                    at=days(30))
    fx.fake("codesign", {hook: "adhoc", proxy: "developer:FIXTURE000", xcode: "apple"})
    procs(r,
          with_env(proc(4200, 50, shell, hours(3)), ["HOME=" + fx.home, "DYLD_INSERT_LIBRARIES=" + hook]),
          with_env(proc(4201, 4200, tool, hours(2)), ["DYLD_INSERT_LIBRARIES=" + hook + ":" + proxy]),   # shell 起的：继承了
          with_env(proc(4202, 50, tool, hours(1)), ["DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib"]),  # 系统的 Guard Malloc
          with_env(proc(4203, 50, tool, hours(1)), ["DYLD_INSERT_LIBRARIES=" + xcode]),                   # Xcode 调试时设的
          with_env(proc(4204, 50, tool, hours(1)), ["DYLD_LIBRARY_PATH=/opt/lib"]),
          with_env(proc(4205, 50, "/opt/io-example/daemon", hours(1), uid=0), ["DYLD_INSERT_LIBRARIES=" + hook]),  # 别的用户的
          proc(4206, 50, tool, hours(1)))                                                                   # 读不到环境变量
    r.update()
    r.scan(T0)


def with_libs(p: Dict[str, Any], libs: List[tuple]) -> Dict[str, Any]:
    """进程映射成代码的文件（程序自己不算）：(路径, 是不是已经删掉)；不带的是读不到。"""
    p["libraries"] = [{"path": path, "deleted": deleted} for path, deleted in libs]
    return p


@case("rules/process/libraries", "进程载入的库：临时文件夹、下载文件夹里的一个程序一条（签名对不上的高），文件已经删掉的一个程序一条；"
      "苹果自己的、应用自己包里的（App Translocation 搬到临时文件夹的应用也是）、苹果签名的、程序本身已经删掉的、别的用户的、读不到的不报；"
      "只是放在叫 AppTranslocation 的文件夹里的照报")
def process_libraries(r: Run) -> None:
    fx = r.fx
    tool, server, other = prog(fx, "~/.local/bin/tool"), prog(fx, "~/.local/bin/server"), prog(fx, "~/.local/bin/other")
    # 从下载里直接打开的应用：macOS 把它挪到临时文件夹下的隐藏位置再跑
    moved = "$TMPDIR/AppTranslocation/0A1B2C3D-0000-4000-8000-000000000000/d/Viewer.app/Contents/"
    viewer = prog(fx, moved + "MacOS/Viewer")
    hook = fx.file("$TMPDIR/io.example-unpack/hook.dylib", "not a real library\n", at=days(1))
    plugin = fx.file("~/Downloads/plugin.dylib", "not a real library\n", at=days(1))
    apple = fx.file("$TMPDIR/apple-signed.dylib", "not a real library\n", at=days(1))
    named = fx.file("$TMPDIR/io.example-named/AppTranslocation/hook.dylib", "not a real library\n", at=days(1))
    fx.fake("codesign", {hook: "adhoc", plugin: "invalid", apple: "apple", named: "adhoc"})
    procs(r,
          with_libs(proc(4400, 50, tool, hours(2)), [(hook, False), (plugin, False), ("/usr/lib/libz.1.dylib", False),
                                                     (fx.p("~/.local/lib/libfine.dylib"), False)]),
          with_libs(proc(4401, 50, tool, hours(1)), [(hook, False)]),
          with_libs(proc(4402, 50, server, days(3)), [(fx.p("~/.local/lib/libold.1.dylib"), True),
                                                      ("/System/Library/Frameworks/Old.framework/Old", True)]),
          with_libs(proc(4403, 50, viewer, hours(1)), [(fx.p(moved + "Frameworks/Kit.framework/Kit"), False)]),  # 它自己包里的
          with_libs(proc(4404, 50, fx.p("~/.local/bin/gone"), hours(1)), [(fx.p("~/.local/lib/libgone.dylib"), True)]),
          with_libs(proc(4405, 50, other, hours(1)), [(apple, False)]),
          with_libs(proc(4406, 50, "/opt/io-example/daemon", hours(1), uid=0), [(hook, False)]),   # 别的用户的
          proc(4407, 50, other, hours(1)),                                                          # 读不到
          with_libs(proc(4408, 50, other, hours(1)), [(named, False)]))                             # 只是名字像
    r.update()
    r.scan(T0)


@case("rules/process/no-process-list", "进程表是空的（读不到）：这条规则记成没扫描")
def process_no_list(r: Run) -> None:
    r.fx.fake("processes", [])
    r.update()
    r.scan(T0)


@case("rules/process/no-full-disk-access", "被删掉的程序在下载、桌面里，有、没有完全磁盘访问各查一轮（没有时本该不去看那里；别处的照报）")
def process_no_fda(r: Run) -> None:
    # 现在没有访问时也照报：假目录在 /private/var/folders 下，程序文件又不在了，「在不在下载里」按 /var/folders 的写法比，
    # 对不上（扫描的毛病，golden 照现在的录）。
    fx = r.fx
    procs(r,
          proc(8401, 50, fx.p("~/Downloads/tool/agent"), days(1)),
          proc(8402, 50, fx.p("~/Desktop/run/helper"), days(1)),
          proc(8403, 50, fx.p("~/bin/gone"), days(1)))
    r.update()
    r.scan(T0, note="有完全磁盘访问")
    r.scan(T0, "--no-full-disk-access", note="没有完全磁盘访问")


# ================================================================ 看键盘的程序（keyboard）

def tap(program: str, *, listen_only: bool = True, all_apps: bool = True, pid: Optional[int] = None) -> Dict[str, Any]:
    return {"program": program, "listenOnly": listen_only, "allApps": all_apps, "pid": pid}


def taps(r: Run, *ts: Dict[str, Any]) -> None:
    r.fx.fake("eventTaps", list(ts))


@case("rules/keyboard/no-window-server", "问不到有哪些键盘监听（没有登录的图形界面）：这条规则记成没扫描")
def keyboard_unknown(r: Run) -> None:
    r.fx.fake("eventTaps", None)
    r.update()
    r.scan(T0)


@case("rules/keyboard/deleted-program", "看所有应用按键的进程，程序文件已经删掉了：每个进程一条，高；只看自己窗口的不报")
def keyboard_deleted(r: Run) -> None:
    taps(r, tap("", pid=4242), tap("", pid=4243, listen_only=False), tap("", pid=4244, all_apps=False))
    r.update()
    r.scan(T0)


@case("rules/keyboard/unvouched", "没人担保的程序在看所有应用的按键：脚本、没签名的文件、没签名的应用、不在了的程序，各一条，高")
def keyboard_unvouched(r: Run) -> None:
    fx = r.fx
    script = prog(fx, "~/.local/bin/keyhelper")
    plain = fx.file("~/bin/keyd", "not a program, not a script\n", mode=0o755, at=days(30))
    app = fx.app("~/Applications/Keys.app", "io.example.keys", "Keys", at=days(30))
    taps(r, tap(script), tap(plain, listen_only=False), tap(app + "/Contents/MacOS/Keys"), tap(fx.p("~/bin/never-there")))
    r.update()
    r.scan(T0)


@case("rules/keyboard/adhoc-and-invalid", "临时签名的程序、临时签名的应用、签名后 Info.plist 又被改过的应用在看所有应用的按键：各一条，高")
def keyboard_adhoc(r: Run) -> None:
    fx = r.fx
    adhoc = fx.file("~/bin/keyd-adhoc", "#?not a script\n" + "x" * 64, mode=0o755, at=days(30))
    fx.adhoc_sign("~/bin/keyd-adhoc")
    signed = fx.app("~/Applications/KeysAdhoc.app", "io.example.keys-adhoc", "KeysAdhoc", at=days(30))
    fx.adhoc_sign("~/Applications/KeysAdhoc.app")
    changed = fx.app("~/Applications/KeysChanged.app", "io.example.keys-changed", "KeysChanged", at=days(30))
    fx.adhoc_sign("~/Applications/KeysChanged.app")
    # 签名以后 Info.plist 又改了：签名和文件对不上。
    fx.plist("~/Applications/KeysChanged.app/Contents/Info.plist",
             {"CFBundleIdentifier": "io.example.keys-changed", "CFBundleName": "KeysChanged", "CFBundleExecutable": "KeysChanged",
              "LSUIElement": True}, at=days(30))
    taps(r, tap(adhoc), tap(signed + "/Contents/MacOS/KeysAdhoc"), tap(changed + "/Contents/MacOS/KeysChanged"))
    r.update()
    r.scan(T0)


@case("rules/keyboard/homebrew", "Homebrew 的目录里没签名（这里是不在了）的快捷键工具：多半是快捷键工具，中")
def keyboard_homebrew(r: Run) -> None:
    taps(r, tap("/opt/homebrew/Cellar/io-example-hotkeys/1.0/bin/io-example-hotkeys", listen_only=False),
         tap("/usr/local/Cellar/io-example-keys/2.0/bin/io-example-keys"),
         tap("/usr/local/opt/io-example-remap/bin/io-example-remap"))
    r.update()
    r.scan(T0)


@case("rules/keyboard/apple-interpreter", "苹果签名的解释器（zsh、python3、osascript）在看按键：在跑的脚本没人担保，中；苹果别的程序、/System 下的不报")
def keyboard_interpreter(r: Run) -> None:
    taps(r, tap("/bin/zsh"), tap("/usr/bin/python3"), tap("/usr/bin/osascript"),
         tap("/usr/bin/true"), tap("/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock"))
    r.update()
    r.scan(T0)


@case("rules/keyboard/own-window-and-duplicates", "只看自己窗口的不报；同一个程序有两个监听只报一条")
def keyboard_dup(r: Run) -> None:
    fx = r.fx
    game = prog(fx, "~/Applications/Game/game")
    keys = prog(fx, "~/.local/bin/keyhelper")
    taps(r, tap(game, all_apps=False, listen_only=False), tap(keys), tap(keys, listen_only=False))
    r.update()
    r.scan(T0)


@case("rules/keyboard/no-full-disk-access", "看按键的程序在下载、文稿里：有完全磁盘访问时按签名报（脚本，高）；没有时不去读它，照样报，中，不当发现的路径")
def keyboard_no_fda(r: Run) -> None:
    fx = r.fx
    taps(r, tap(prog(fx, "~/Downloads/keys/helper")), tap(prog(fx, "~/Documents/tools/keytap")))
    r.update()
    r.scan(T0, note="有完全磁盘访问")
    r.scan(T0, "--no-full-disk-access", note="没有完全磁盘访问")


# ================================================================ 对外露出的（exposure）：SSH

# 钥匙的头尾拼出来写，这份源码里没有整行的私钥头（免得被查泄露的工具当成私钥）。内容都是编的，不是能用的钥匙。
_BEGIN, _END, _PK = "-----BEGIN ", "-----END ", "PRIVATE " + "KEY-----"


def _s(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def openssh(cipher: str, pub: bytes) -> str:
    """OpenSSH 格式的私钥（openssh-key-v1）：只有扫描看的部分对——加密方式和公钥。"""
    raw = (b"openssh-key-v1\0" + _s(cipher.encode()) + _s(b"none" if cipher == "none" else b"bcrypt") + _s(b"")
           + (1).to_bytes(4, "big") + _s(pub) + _s(bytes([1, 2, 3, 4])))
    body = base64.b64encode(raw).decode()
    lines = [body[i:i + 70] for i in range(0, len(body), 70)]
    return "\n".join([_BEGIN + "OPENSSH " + _PK, *lines, _END + "OPENSSH " + _PK]) + "\n"


def ed25519() -> bytes:
    return _s(b"ssh-ed25519") + _s(bytes([7] * 32))


def rsa(bits: int) -> bytes:
    return _s(b"ssh-rsa") + _s(b"\x01\x00\x01") + _s(b"\x00" + b"\xc3" * (bits // 8))


def dss() -> bytes:
    return _s(b"ssh-dss") + _s(b"\x00" + b"\xc3" * 128) + _s(b"\x00" + b"\xc3" * 20)


def fido() -> bytes:
    return _s(b"sk-ssh-ed25519@openssh.com") + _s(bytes([7] * 32)) + _s(b"ssh:")


def pem(kind: str, *, encrypted: bool = False) -> str:
    """PEM 格式的私钥：kind 是 RSA、DSA、EC（老格式），"" 是 PKCS#8，ENCRYPTED 是加了密的 PKCS#8。"""
    head = (kind + " " if kind else "") + _PK
    lines = [_BEGIN + head]
    if encrypted:
        lines += ["Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,00", ""]
    lines += ["MIIEAAAA", _END + head]
    return "\n".join(lines) + "\n"


def ssh_dir(fx: Fx, files: Dict[str, Any], *, mode: int = 0o700) -> None:
    """~/.ssh：{名字: (内容, 权限)}，最后设 ~/.ssh 自己的权限。"""
    for name, (text, m) in files.items():
        fx.file("~/.ssh/" + name, text, mode=m, at=days(30))
    fx.dir("~/.ssh", mode=mode)


@case("rules/exposure/ssh-key-plain", "没设口令的 ed25519 私钥：报一条；公钥、known_hosts、config 不看")
def exposure_plain(r: Run) -> None:
    ssh_dir(r.fx, {"id_ed25519": (openssh("none", ed25519()), 0o600),
                   "id_ed25519.pub": ("ssh-ed25519 AAAAexample laptop\n", 0o644),
                   "known_hosts": ("host.example ssh-ed25519 AAAAexample\n", 0o644),
                   "config": ("Host *\n  UseKeychain yes\n", 0o644)})
    r.update()
    r.scan(T0)


@case("rules/exposure/ssh-key-locked", "设了口令的私钥（OpenSSH、老的 RSA、加密的 PKCS#8）、没口令但要插硬件钥匙的（sk-）：都不报")
def exposure_locked(r: Run) -> None:
    ssh_dir(r.fx, {"id_ed25519": (openssh("aes256-ctr", ed25519()), 0o600),
                   "id_rsa": (pem("RSA", encrypted=True), 0o600),
                   "id_pkcs8": (pem("ENCRYPTED"), 0o600),
                   "id_ed25519_sk": (openssh("none", fido()), 0o600)})
    r.update()
    r.scan(T0)


@case("rules/exposure/ssh-key-weak", "太弱的私钥：1024 位的 RSA（有口令的只报弱，没口令的两条都报）、DSA（OpenSSH 和老格式）；3072 位的 RSA 不报")
def exposure_weak(r: Run) -> None:
    ssh_dir(r.fx, {"id_rsa_old": (openssh("aes256-ctr", rsa(1024)), 0o600),
                   "id_rsa_old_plain": (openssh("none", rsa(1024)), 0o600),
                   "id_rsa_ok": (openssh("aes256-ctr", rsa(3072)), 0o600),
                   "id_dsa": (openssh("aes256-ctr", dss()), 0o600),
                   "id_dsa_pem": (pem("DSA", encrypted=True), 0o600)})
    r.update()
    r.scan(T0)


@case("rules/exposure/ssh-key-pem-plain", "老格式没口令的私钥：RSA、EC、PKCS#8 各报一条，写着是哪种")
def exposure_pem(r: Run) -> None:
    ssh_dir(r.fx, {"legacy_rsa": (pem("RSA"), 0o600),
                   "legacy_ec": (pem("EC"), 0o600),
                   "legacy_pkcs8": (pem(""), 0o600)})
    r.update()
    r.scan(T0)


@case("rules/exposure/ssh-key-perm", "别人能读的私钥：644、640、604 各报一条（看不懂格式的也报）；600、400 不报")
def exposure_perm(r: Run) -> None:
    locked = openssh("aes256-ctr", ed25519())
    ssh_dir(r.fx, {"id_world": (locked, 0o644),
                   "id_group": (locked, 0o640),
                   "id_odd": (_BEGIN + "OPENSSH " + _PK + "\nnot base64 at all\n", 0o604),
                   "id_ok": (locked, 0o600),
                   "id_readonly": (locked, 0o400)})
    r.update()
    r.scan(T0)


@case("rules/exposure/ssh-key-not-looked", "~/.ssh 里不当私钥看的：链接、子文件夹里的、超过 64 KB 的、开头不是私钥头的（都是别人能读的权限）")
def exposure_skipped(r: Run) -> None:
    fx = r.fx
    plain = openssh("none", ed25519())
    ssh_dir(fx, {"keys/id_shared": (plain, 0o644),
                 "id_big": (plain + "#" * (70 << 10), 0o644),
                 "id_rsa": ("this is not a key\n", 0o644)})
    fx.link("~/.ssh/id_shared", "keys/id_shared")
    r.update()
    r.scan(T0)


@case("rules/exposure/ssh-dir-perm", "~/.ssh 别人也能写（777）：报；改成 755 以后不报")
def exposure_dir_perm(r: Run) -> None:
    fx = r.fx
    ssh_dir(fx, {"id_ed25519": (openssh("aes256-ctr", ed25519()), 0o600)}, mode=0o777)
    r.update()
    r.scan(T0)
    fx.dir("~/.ssh", mode=0o755)
    r.note("~/.ssh 改成 755")
    r.scan(after(1))


@case("rules/exposure/ssh-authorized", "authorized_keys 里有 2 把钥匙（注释、空行不算）：报一条；后来加了一把，是新的一条（编号跟着钥匙变）")
def exposure_authorized(r: Run) -> None:
    fx = r.fx
    ssh_dir(fx, {"authorized_keys": ("# 自己的\nssh-ed25519 AAAAexample1 laptop\n\n  ssh-rsa AAAAexample2 work  \n", 0o600)})
    r.update()
    r.scan(T0)
    fx.file("~/.ssh/authorized_keys", "# 自己的\nssh-ed25519 AAAAexample1 laptop\n\nssh-rsa AAAAexample2 work\nssh-ed25519 AAAAexample3 new\n",
            mode=0o600, at=after(0.5))
    r.note("authorized_keys 里加了一把")
    r.scan(after(1))


@case("rules/exposure/ssh-authorized-empty", "authorized_keys 里只有注释和空行：不报")
def exposure_authorized_empty(r: Run) -> None:
    ssh_dir(r.fx, {"authorized_keys": ("# 没有钥匙\n\n   \n# ssh-ed25519 AAAAexample old\n", 0o600)})
    r.update()
    r.scan(T0)


@case("rules/exposure/ssh-rc", "有 ~/.ssh/rc（每次 SSH 登录都先跑它）：报一条")
def exposure_rc(r: Run) -> None:
    ssh_dir(r.fx, {"rc": ("#!/bin/sh\necho welcome\n", 0o700)})
    r.update()
    r.scan(T0)


@case("rules/exposure/ssh-linked-dir", "~/.ssh 是链到别处的链接：私钥和文件夹权限不看；authorized_keys、rc 顺着链接照报")
def exposure_linked(r: Run) -> None:
    fx = r.fx
    fx.file("~/dotfiles/ssh/authorized_keys", "ssh-ed25519 AAAAexample1 laptop\n", mode=0o600, at=days(30))
    fx.file("~/dotfiles/ssh/rc", "#!/bin/sh\necho welcome\n", mode=0o700, at=days(30))
    fx.file("~/dotfiles/ssh/id_ed25519", openssh("none", ed25519()), mode=0o644, at=days(30))   # 没口令、别人能读
    fx.dir("~/dotfiles/ssh", mode=0o777)
    fx.link("~/.ssh", "dotfiles/ssh")
    r.update()
    r.scan(T0)


# ================================================================ 安全设置（posture）

SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


@case("rules/posture/filevault-off", "FileVault 没开：高")
def posture_filevault(r: Run) -> None:
    r.fx.command("/usr/bin/fdesetup", "FileVault is Off.\n")
    r.update()
    r.scan(T0)


@case("rules/posture/firewall-off", "防火墙没开：中；隐身模式就不再问了")
def posture_firewall(r: Run) -> None:
    r.fx.command(SOCKETFILTERFW, "Firewall is disabled. (State = 0)\n", args=["--getglobalstate"])
    r.fx.command(SOCKETFILTERFW, "Firewall stealth mode is off. (State = 0)\n", args=["--getstealthmode"])
    r.update()
    r.scan(T0)


@case("rules/posture/stealth-off", "防火墙开着、隐身模式没开：低；隐身模式开了以后不报")
def posture_stealth(r: Run) -> None:
    r.fx.command(SOCKETFILTERFW, "Firewall stealth mode is off. (State = 0)\n", args=["--getstealthmode"])
    r.update()
    r.scan(T0)
    r.fx.command(SOCKETFILTERFW, "Firewall stealth mode is on. (State = 1)\n", args=["--getstealthmode"])
    r.note("隐身模式打开")
    r.scan(after(1))


@case("rules/posture/sip-off", "系统完整性保护（SIP）关着：高")
def posture_sip(r: Run) -> None:
    r.fx.command("/usr/bin/csrutil", "System Integrity Protection status: disabled.\n")
    r.update()
    r.scan(T0)


@case("rules/posture/gatekeeper-off", "Gatekeeper 关着：高")
def posture_gatekeeper(r: Run) -> None:
    r.fx.command("/usr/sbin/spctl", "assessments disabled\n")
    r.update()
    r.scan(T0)


@case("rules/posture/screen-lock-off", "锁屏不要密码：中")
def posture_screen_lock(r: Run) -> None:
    r.fx.command("/bin/sh", "sysadminctl[1:2] screenLock is off\n")
    r.update()
    r.scan(T0)


@case("rules/posture/screen-lock-delay", "锁屏 900 秒后才要密码：低（写成 15 分钟）；改成 300 秒（正好 5 分钟）以后不报")
def posture_screen_delay(r: Run) -> None:
    r.fx.command("/bin/sh", "sysadminctl[1:2] screenLock delay is 900 seconds\n")
    r.update()
    r.scan(T0)
    r.fx.command("/bin/sh", "sysadminctl[1:2] screenLock delay is 300 seconds\n")
    r.note("锁屏改成 300 秒")
    r.scan(after(1))


@case("rules/posture/screen-lock-unknown", "锁屏的答复看不懂：不当没毛病，记进「有几项没查成」")
def posture_screen_unknown(r: Run) -> None:
    r.fx.command("/bin/sh", "sysadminctl[1:2] something unexpected\n")
    r.update()
    r.scan(T0)


@case("rules/posture/autoupdate-off", "系统不自动检查更新（AutomaticCheckEnabled 是 0）：中")
def posture_autoupdate(r: Run) -> None:
    r.fx.command("/usr/bin/defaults", "0\n", args=["AutomaticCheckEnabled"])
    r.update()
    r.scan(T0)


@case("rules/posture/pending-updates", "45 天没重启、2 个更新等着装：低；29 天、没有更新、开机时间不知道、更新数不知道时都不报")
def posture_pending(r: Run) -> None:
    fx = r.fx
    fx.fake("bootTime", iso(days(45)))
    fx.fake("pendingUpdates", 2)
    r.update()
    r.scan(T0)
    fx.fake("bootTime", iso(days(29)))
    r.note("29 天前开的机")
    r.scan(T0)
    fx.fake("bootTime", iso(days(79)))
    fx.fake("pendingUpdates", 0)
    r.note("79 天前开的机，没有等着装的更新")
    r.scan(T0)
    fx.fake("bootTime", None)
    fx.fake("pendingUpdates", 3)
    r.note("不知道什么时候开的机，3 个更新")
    r.scan(T0)
    fx.fake("bootTime", iso(days(79)))
    fx.fake("pendingUpdates", None)
    r.note("79 天前开的机，不知道有几个更新")
    r.scan(T0)


@case("rules/posture/uptime-exactly-30-days", "正好 30 天没重启、1 个更新等着装：报（30 天起算）")
def posture_pending_edge(r: Run) -> None:
    r.fx.fake("bootTime", iso(days(30)))
    r.fx.fake("pendingUpdates", 1)
    r.update()
    r.scan(T0)


LAUNCHCTL_ON = ("disabled services = {\n\t\"com.openssh.sshd\" => enabled\n\t\"com.apple.screensharing\" => enabled\n"
                "\t\"com.apple.smbd\" => enabled\n\t\"com.apple.NetworkSharing\" => enabled\n\t\"io.example.other\" => enabled\n}\n")


@case("rules/posture/sharing-on", "远程登录、屏幕共享、文件共享、互联网共享都开着：各一条")
def posture_sharing(r: Run) -> None:
    r.fx.command("/bin/launchctl", LAUNCHCTL_ON, args=["print-disabled"])
    r.update()
    r.scan(T0)


@case("rules/posture/sharing-old-format", "老系统的写法：「=> false」算开着；「=> true」「=> disabled」算关着")
def posture_sharing_old(r: Run) -> None:
    r.fx.command("/bin/launchctl", "disabled services = {\n\t\"com.openssh.sshd\" => false\n\t\"com.apple.screensharing\" => true\n"
                 "\t\"com.apple.smbd\" => disabled\n}\n", args=["print-disabled"])
    r.update()
    r.scan(T0)


@case("rules/posture/airdrop-everyone", "隔空投送对所有人开着：低")
def posture_airdrop(r: Run) -> None:
    r.fx.command("/usr/bin/defaults", "Everyone\n", args=["DiscoverableMode"])
    r.update()
    r.scan(T0)


@case("rules/posture/auto-login-and-guest", "开机自动登录（高）、客人用户开着（低）：各一条")
def posture_login(r: Run) -> None:
    r.fx.command("/usr/bin/defaults", "example-user\n", args=["autoLoginUser"])
    r.fx.command("/usr/bin/defaults", "1\n", args=["GuestEnabled"])
    r.update()
    r.scan(T0)


TRUST_USER = """Number of trusted certs = 3
Cert 0: Example Debug Proxy CA
   Number of trust settings : 0
Cert 1: Example Bad CA
   Number of trust settings : 1
   Trust Setting 0:
      Result Type           : kSecTrustSettingsResultDeny
Cert 2: nas.example
   Number of trust settings : 1
   Trust Setting 0:
      Policy OID            : SSL
      Policy String         : nas.example
      Result Type           : kSecTrustSettingsResultTrustRoot
"""

NO_TRUST = "SecTrustSettings: No Trust Settings were found.\n"

TRUST_ADMIN = """Number of trusted certs = 1
Cert 0: Example Corp Root
   Number of trust settings : 1
   Trust Setting 0:
      Policy OID            : SSL
      Result Type           : kSecTrustSettingsResultTrustRoot
"""


@case("rules/posture/trusted-roots", "加进来的根证书被设成信任（本用户的、管理员的）：合成一条；不信任的、只给一台主机用的不算；后来又加一个是新的一条")
def posture_roots(r: Run) -> None:
    fx = r.fx
    # 答复按「第一条参数都对上的」挑：-d（管理员的）要写在前面，不然本用户那条也答给它。
    fx.command("/usr/bin/security", TRUST_USER, args=["dump-trust-settings"])
    fx.command("/usr/bin/security", NO_TRUST, args=["dump-trust-settings", "-d"], status=1)
    r.update()
    r.scan(T0)
    fx.command("/usr/bin/security", TRUST_ADMIN, args=["dump-trust-settings", "-d"])
    r.note("管理员也加了一个根证书")
    r.scan(after(1))


@case("rules/posture/trusted-roots-both-domains", "同一个根证书本用户、管理员都设了信任：算一个")
def posture_roots_twice(r: Run) -> None:
    # 本用户那条答复不写 -d，两次问都答它：同一个证书出现在两份信任设置里。
    r.fx.command("/usr/bin/security", TRUST_ADMIN, args=["dump-trust-settings"])
    r.update()
    r.scan(T0)


@case("rules/posture/trusted-roots-none", "根证书都是不信任的、只给一台主机用的：不报")
def posture_roots_none(r: Run) -> None:
    lines = TRUST_USER.split("Cert 0:")[0] + "Cert 1:" + TRUST_USER.split("Cert 1:")[1]
    r.fx.command("/usr/bin/security", lines, args=["dump-trust-settings"])
    r.update()
    r.scan(T0)


@case("rules/posture/xprotect-stale", "XProtect 61 天没更新：中；正好 60 天、不知道什么时候更新的不报")
def posture_xprotect(r: Run) -> None:
    fx = r.fx
    fx.fake("xprotectUpdated", iso(days(61)))
    r.update()
    r.scan(T0)
    fx.fake("xprotectUpdated", iso(days(60)))
    r.note("XProtect 60 天前更新的")
    r.scan(T0)
    fx.fake("xprotectUpdated", None)
    r.note("不知道 XProtect 什么时候更新的")
    r.scan(T0)


@case("rules/posture/probes-failed", "命令跑不了（超时）、出错又没输出的：每一项都记进「有几项没查成」，不当没毛病")
def posture_failed(r: Run) -> None:
    fx = r.fx
    fx.command("/usr/bin/fdesetup", "", status=-1)
    fx.command(SOCKETFILTERFW, "", status=-1)
    fx.command("/usr/bin/csrutil", "", status=1)
    fx.command("/usr/sbin/spctl", "", status=-1)
    fx.command("/bin/sh", "", status=-1)
    fx.command("/bin/launchctl", "", status=113)
    r.update()
    r.scan(T0)


@case("rules/posture/stealth-probe-failed", "防火墙开着但隐身模式问不到：记「防火墙隐身模式」没查成")
def posture_stealth_failed(r: Run) -> None:
    r.fx.command(SOCKETFILTERFW, "", args=["--getstealthmode"], status=-1)
    r.update()
    r.scan(T0)


@case("rules/posture/unit-test-mac", "单元测试那份标准的假答案（FileVault 关着、1 个更新、开机 79 天、Gatekeeper 问不到）：只看安全设置这几条", quiet=False)
def posture_standard(r: Run) -> None:
    # 只留安全设置要的：进程表换成一个开着的应用，免得进程那条规则的发现混进来。
    r.fx.fake("processes", [proc(400, 1, "/Applications/Safari.app/Contents/MacOS/Safari", days(1))])
    r.fx.fake("launchdPIDs", [])
    r.update()
    r.scan(T0)


# ================================================================ 病毒扫描（malware）

# 假的 clamscan 外面再包一层：每次扫描把交给它的文件列表抄下来，看一轮里哪些文件真的又扫了一遍。
_WATCH = """#!/bin/sh
d=$(dirname "$0")
for a in "$@"; do case "$a" in --file-list=*) echo "---" >> "$d/handed.log"; cat "${a#--file-list=}" >> "$d/handed.log";; esac; done
exec "$d/clamscan-inner" "$@"
"""


def watch_clamscan(fx: Fx) -> None:
    path = os.path.join(fx.tools, "clamscan")
    os.rename(path, path + "-inner")
    with open(path, "w") as f:
        f.write(_WATCH)
    os.chmod(path, 0o755)


def handed(r: Run) -> None:
    """记一步：上一步查的时候交给 clamscan 扫的文件（没起 clamscan 就写没起）。"""
    log = os.path.join(r.fx.tools, "handed.log")
    runs: List[List[str]] = []
    if os.path.exists(log):
        with open(log, encoding="utf-8") as f:
            for line in f.read().splitlines():
                if line == "---":
                    runs.append([])
                elif line:
                    runs[-1].append(line)
        os.remove(log)
    r.note("交给 clamscan 的：" + ("没起 clamscan" if not runs else " | ".join("、".join(run) for run in runs)))


def replace_tool(fx: Fx, name: str, script: str) -> None:
    """假目录里的一个扫描器换成另一个小脚本（坏掉的扫描器）。"""
    path = os.path.join(fx.tools, name)
    with open(path, "w") as f:
        f.write(script)
    os.chmod(path, 0o755)


# ---- 病毒库

@case("rules/malware/db-none", "还没下载病毒库：病毒扫描记成没扫描（叫你先 update）")
def malware_db_none(r: Run) -> None:
    r.fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    r.scan(T0)


@case("rules/malware/db-first-update-fails", "第一次下载病毒库就失败：update 退出码 1、说没下载成（没有旧库可保留）；查的时候还是没有病毒库")
def malware_db_first_fail(r: Run) -> None:
    r.fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    r.fx.tool_flag("fail-next")
    r.update()
    r.scan(T0)


@case("rules/malware/db-first-round", "还没有病毒库时第一轮先下载（--update-first；这台 Mac 上 --this-mac 一直这样）：这一轮就查了病毒")
def malware_db_first_round(r: Run) -> None:
    r.fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    r.scan(T0, "--update-first")
    r.scan(T0 + datetime.timedelta(hours=1), "--update-first")  # 有库了：不再下载


@case("rules/malware/db-first-round-fails", "第一轮先下载病毒库没下成：照常查，病毒那一项说没下载")
def malware_db_first_round_fails(r: Run) -> None:
    r.fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    r.fx.tool_flag("fail-next")
    r.scan(T0, "--update-first")


@case("rules/malware/db-stale", "病毒库 20 天没更新：照样扫（认得的照报），再加一条「病毒库多少天没更新」")
def malware_db_stale(r: Run) -> None:
    r.fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    r.fx.tool_flag("db-date", "202609300100")
    r.update()
    r.scan(T0)


@case("rules/malware/db-stale-edge", "病毒库正好 14 天：不算旧；14 天零 1 分钟：算旧（写 14 天）")
def malware_db_stale_edge(r: Run) -> None:
    r.fx.tool_flag("db-date", "202610061200")
    r.update()
    r.scan(T0)
    r.scan(T0 + datetime.timedelta(minutes=1))


@case("rules/malware/db-update-fails-later", "病毒库下过一次，后来更新失败：旧库照用；旧了以后「没更新」那条带着上次的错")
def malware_db_fail_later(r: Run) -> None:
    fx = r.fx
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    fx.tool_flag("db-date", "202609250100")
    r.update()
    fx.tool_flag("fail-next")
    r.update()
    r.scan(T0)


@case("rules/malware/db-bad-download", "下来一个坏的病毒库（校验不过）：update 退出码 1、保留旧库；查的时候用的还是旧库的版本")
def malware_db_bad(r: Run) -> None:
    fx = r.fx
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    r.update()
    fx.tool_flag("bad-next")
    r.update()
    r.scan(T0)


@case("rules/malware/db-up-to-date", "freshclam 说已经是最新的：update 照说，库不变")
def malware_db_same(r: Run) -> None:
    fx = r.fx
    r.update()
    fx.tool_flag("same-next")
    r.update()
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    r.scan(T0)


@case("rules/malware/db-new-version", "病毒库换了新版本（31000，第二天 31001）：报告写着新的版本；没变的文件从记录报，还写着扫它时的版本")
def malware_db_version(r: Run) -> None:
    fx = r.fx
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(3))
    fx.tool_flag("next-version", "31000")
    r.update()
    r.scan(T0)
    fx.tool_flag("db-date", "202610210100")   # 新库的文件时间也是新的（时间不变的话 update 当成已经是最新的）
    r.update()
    r.scan(after(1))


@case("rules/malware/db-freshclam-odd", "freshclam 的两种怪答复：被上游限流（退出码 1 也不当成已经是最新的）、说成功了却没有库文件：都算更新失败")
def malware_db_odd(r: Run) -> None:
    fx = r.fx
    replace_tool(fx, "freshclam", "#!/bin/sh\n"
                 'echo "WARNING: FreshClam received error code 429 from the ClamAV Content Delivery Network (CDN)."\n'
                 'echo "You are on cool-down until after: 2026-10-21 12:00:00"\nexit 1\n')
    r.update()
    replace_tool(fx, "freshclam", "#!/bin/sh\nexit 0\n")
    r.note("换成一个什么都不下的 freshclam")
    r.update()
    r.scan(T0)


# ---- 认出来的

@case("rules/malware/clamav-download", "下载里最近来的、病毒库认得的文件：报，高；100 天前来的不扫；文件日期老但最近才放进来的照扫")
def malware_clamav(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    fx.file("~/Downloads/old-eicar.zip", size=100, at=days(100))
    fx.file("~/Downloads/eicar-kept-date.zip", size=100, at=days(400), added=days(1))
    fx.file("~/Downloads/notes.txt", "just notes\n", at=days(3))
    r.update()
    r.scan(T0)
    handed(r)


@case("rules/malware/yara-password-dialog", "YARA 认出伪造的要密码的对话框脚本：报，高，写着规则包的版本")
def malware_yara(r: Run) -> None:
    r.fx.file("~/Downloads/update.scpt", 'do shell script "x" & (display dialog "macOS needs your password" default answer "" with hidden answer)',
              at=days(1))
    r.update()
    r.scan(T0)


@case("rules/malware/yara-xprotect", "macOS 自带的 XProtect 规则认出的：报，高，写着是 XProtect 的规则")
def malware_xprotect(r: Run) -> None:
    r.fx.file("~/Downloads/installer.pkg", "this one apple knows about\n", at=days(1))
    r.update()
    r.scan(T0)


@case("rules/malware/too-large", "超过 clamscan 限制的大文件：合成一条「几个大文件没做病毒扫描」，不当病毒；第二轮照报，不再起 clamscan")
def malware_too_large(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    fx.file("~/Downloads/huge-installer.dmg", size=1 * MiB, at=days(1))
    fx.file("~/Downloads/huge-backup.zip", size=2 * MiB, at=days(2))
    r.update()
    r.scan(T0)
    handed(r)
    r.scan(after(1))
    handed(r)


@case("rules/malware/partial", "没扫成的：打不开的、clamscan 读不了的、YARA 读不了的，合成一条「几个文件没扫成」；下一轮再扫（打不开的不交给扫描器）")
def malware_partial(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    fx.file("~/Downloads/locked.bin", size=100, at=days(1), mode=0o000)
    fx.file("~/Downloads/unreadable-archive.zip", size=100, at=days(1))
    fx.file("~/Downloads/yara-error.js", size=100, at=days(1))
    fx.file("~/Downloads/fine.txt", "fine\n", at=days(1))
    r.update()
    r.scan(T0)
    handed(r)
    r.scan(after(1))
    handed(r)


@case("rules/malware/odd-name", "文件名里有换行：不交给扫描器，报一条「文件名里有控制字符」")
def malware_odd_name(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    fx.file("~/Downloads/invoice\nfinal.pdf", size=100, at=days(1))
    fx.file("~/Downloads/fine.txt", "fine\n", at=days(1))
    r.update()
    r.scan(T0)
    handed(r)


@case("rules/malware/app-partial", "下载来的应用只扫里面的程序（MacOS 下的、标了能运行的）：报一条「只扫了 4 个文件里的 2 个」；病毒库认得的程序照报")
def malware_app(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    app = "~/Downloads/Tool.app"
    fx.app(app, "io.example.tool", "Tool", at=days(1))
    fx.file(app + "/Contents/Resources/icon.icns", size=1024, at=days(1))
    fx.file(app + "/Contents/Resources/eicar-helper.sh", "#!/bin/sh\nexit 0\n", mode=0o755, at=days(1))
    for d in ["/Contents/MacOS", "/Contents/Resources", "/Contents", ""]:
        fx.touch(app + d, days(1))
    r.update()
    r.scan(T0)
    handed(r)


@case("rules/malware/app-many-programs", "下载来的应用里标了能运行的文件有 60 个：MacOS 下的全扫，别的只扫 50 个；排在后面的病毒程序没扫到")
def malware_app_many(r: Run) -> None:
    fx = r.fx
    app = "~/Downloads/Bundle.app"
    fx.app(app, "io.example.bundle", "Bundle", at=days(1))
    for i in range(60):
        fx.file(app + f"/Contents/Resources/bin/tool-{i:02d}", "#!/bin/sh\nexit 0\n", mode=0o755, at=days(1))
    fx.file(app + "/Contents/Resources/bin/zz-eicar-last", "#!/bin/sh\nexit 0\n", mode=0o755, at=days(1))
    for d in ["/Contents/MacOS", "/Contents/Resources/bin", "/Contents/Resources", "/Contents", ""]:
        fx.touch(app + d, days(1))
    r.update()
    r.scan(T0)


@case("rules/malware/not-taken", "下载里不扫的：下了一半的（.crdownload、.download 文件夹）、._ 和 .DS_Store、node_modules、.git 里的、日期在以后的")
def malware_not_taken(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    for rel in ["eicar.zip.crdownload", "eicar.part", "Movie.download/eicar-inside", "._eicar.com", ".DS_Store",
                "project/node_modules/eicar/index.js", "repo/.git/eicar-object"]:
        fx.file("~/Downloads/" + rel, size=100, at=days(1))
    fx.file("~/Downloads/eicar-future.bin", size=100, at=after(10))
    fx.file("~/Downloads/fine.txt", "fine\n", at=days(1))
    for d in ["Movie.download", "project/node_modules/eicar", "project/node_modules", "project", "repo/.git", "repo"]:
        fx.touch("~/Downloads/" + d, days(1))
    r.update()
    r.scan(T0)
    handed(r)


@case("rules/malware/spotlight-downloaded", "Spotlight 说是下载来的、不在下载文件夹里的：最近来的照扫；老的、应用里面的不扫")
def malware_spotlight(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    chat = fx.file("~/Desktop/eicar-from-chat.pdf", size=100, at=days(3))
    old = fx.file("~/Projects/assets/eicar-old.bin", size=100, at=days(100))
    inner = fx.file("~/Applications/Fetched.app/Contents/Resources/eicar-inner.bin", size=100, at=days(1))
    dl = fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    fx.fake("downloaded", [chat, old, inner, dl])
    r.update()
    r.scan(T0)
    handed(r)


@case("rules/malware/launch-agent-program", "后台任务（LaunchAgent）起的程序：不管多老都扫；链接顺着找到真的文件扫；病毒库认得的报")
def malware_agent(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    real = fx.file("~/.local/share/io.example/eicar-real", "#!/bin/sh\nexit 0\n", mode=0o755, at=days(400))
    fx.link("~/.local/bin/agent-link", real)
    fx.file("~/.local/bin/eicar-agent", "#!/bin/sh\nexit 0\n", mode=0o755, at=days(400))
    fx.file("~/.local/bin/clean-agent", "#!/bin/sh\nexit 0\n", mode=0o755, at=days(400))
    la = "~/Library/LaunchAgents/"
    fx.plist(la + "io.example.one.plist", {"Label": "io.example.one", "ProgramArguments": [fx.p("~/.local/bin/eicar-agent"), "--serve"]}, at=days(400))
    fx.plist(la + "io.example.two.plist", {"Label": "io.example.two", "Program": fx.p("~/.local/bin/agent-link")}, at=days(400))
    fx.plist(la + "io.example.three.plist", {"Label": "io.example.three", "ProgramArguments": [fx.p("~/.local/bin/clean-agent")]},
             at=days(400))
    r.update()
    r.scan(T0)
    handed(r)


def as_scan_sees(path: str) -> str:
    """扫描拿到的假目录的根是 /var/… 的写法（没有 /private），正在运行的程序照这个写法写才算在假目录里、才交给病毒扫描。"""
    return path[len("/private"):] if path.startswith("/private/var/") else path


def running(p: Dict[str, Any], args: List[str], cwd: Optional[str] = None) -> Dict[str, Any]:
    """进程的命令行（argv）和工作目录；不带工作目录的是读不到。"""
    p["arguments"] = args
    if cwd is not None:
        p["cwd"] = cwd
    return p


@case("rules/malware/running-relative-script", "解释器用相对路径跑的脚本：在它的工作目录里找到再扫，不管多老；"
      "读不到工作目录的、命令行上直接给代码的不扫")
def malware_running_relative(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    node = as_scan_sees(prog(fx, "~/.local/bin/node"))
    site = as_scan_sees(fx.p("~/Projects/site"))
    fx.file("~/Projects/site/eicar-server.js", "console.log(1)\n", at=days(400))
    fx.file("~/Projects/site/clean.js", "console.log(2)\n", at=days(400))
    fx.file("~/Projects/site/eicar-unread.js", "console.log(3)\n", at=days(400))
    procs(r,
          running(proc(4300, 50, node, hours(2)), ["node", "./eicar-server.js"], cwd=site),
          running(proc(4301, 50, node, hours(2)), ["node", "--inspect", "clean.js"], cwd=site),
          running(proc(4302, 50, node, hours(2)), ["node", "eicar-unread.js"]),                  # 读不到工作目录
          running(proc(4303, 50, node, hours(2)), ["node", "-e", "eicar-unread.js"], cwd=site))  # 命令行上给的代码
    r.update()
    r.scan(T0)
    handed(r)


@case("rules/malware/running-libraries", "正在运行的程序载入的库也扫，不管多老：应用自己包里的不扫（随应用来的），苹果自己的不扫；"
      "病毒库认得的报")
def malware_running_libraries(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    tool = as_scan_sees(prog(fx, "~/.local/bin/tool"))
    viewer = as_scan_sees(prog(fx, "~/Applications/Viewer.app/Contents/MacOS/Viewer"))
    own = as_scan_sees(fx.file("~/Applications/Viewer.app/Contents/Frameworks/Kit.framework/Kit", "x\n", at=days(400)))
    plugin = as_scan_sees(fx.file("~/Library/Application Support/io.example/eicar-plugin.dylib", "x\n", at=days(400)))
    clean = as_scan_sees(fx.file("~/.local/lib/libclean.dylib", "x\n", at=days(400)))
    procs(r,
          with_libs(proc(4500, 50, viewer, hours(1)), [(own, False), (plugin, False), ("/usr/lib/libz.1.dylib", False)]),
          with_libs(proc(4501, 50, tool, hours(1)), [(clean, False)]))
    r.update()
    r.scan(T0)
    handed(r)


@case("rules/malware/skill-files", "AI 工具的 skill 里的文件：不管多老都扫；病毒库认得的报")
def malware_skill(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    fx.file("~/.claude/skills/helper/SKILL.md", "---\nname: helper\ndescription: 帮忙整理笔记\n---\n\n整理笔记。\n", at=days(200))
    fx.file("~/.claude/skills/helper/scripts/eicar-payload.sh", "#!/bin/sh\nexit 0\n", mode=0o755, at=days(200))
    r.update()
    r.scan(T0)
    handed(r)


@case("rules/malware/no-full-disk-access", "没有完全磁盘访问：下载、桌面里的不看，规则记成只扫了一部分；后台任务的程序照扫照报，链到文稿里的不跟")
def malware_no_fda(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    chat = fx.file("~/Desktop/eicar-from-chat.pdf", size=100, at=days(3))
    fx.fake("downloaded", [chat])
    fx.file("~/.local/bin/eicar-agent", "#!/bin/sh\nexit 0\n", mode=0o755, at=days(400))
    docs = fx.file("~/Documents/scripts/eicar-docs-agent", "#!/bin/sh\nexit 0\n", mode=0o755, at=days(400))
    fx.link("~/.local/bin/docs-link", docs)
    la = "~/Library/LaunchAgents/"
    fx.plist(la + "io.example.one.plist", {"Label": "io.example.one", "ProgramArguments": [fx.p("~/.local/bin/eicar-agent")]}, at=days(400))
    fx.plist(la + "io.example.two.plist", {"Label": "io.example.two", "ProgramArguments": [fx.p("~/.local/bin/docs-link")]}, at=days(400))
    r.update()
    r.scan(T0, "--no-full-disk-access")
    handed(r)


@case("rules/malware/no-fda-keeps-record", "有访问时扫过的下载，一轮没访问时不忘掉：再有访问时不用重扫，发现照报")
def malware_no_fda_record(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    fx.file("~/Downloads/notes.txt", "just notes\n", at=days(2))
    r.update()
    r.scan(T0, note="有完全磁盘访问")
    handed(r)
    r.scan(after(1), "--no-full-disk-access", note="没有完全磁盘访问")
    handed(r)
    r.scan(after(2), note="又有了")
    handed(r)


# ---- 下一轮

@case("rules/malware/rescan-unchanged", "第二天再查，文件都没变：不起 clamscan，上一轮的发现照报")
def malware_rescan_same(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    fx.file("~/Downloads/update.scpt", 'display dialog "password" default answer "" with hidden answer', at=days(2))
    fx.file("~/Downloads/notes.txt", "just notes\n", at=days(2))
    r.update()
    r.scan(T0)
    handed(r)
    r.scan(after(1))
    handed(r)


@case("rules/malware/rescan-after-a-week", "没变的文件，扫过 6 天还从记录报；满 7 天再扫一遍")
def malware_rescan_week(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    fx.file("~/Downloads/notes.txt", "just notes\n", at=days(2))
    r.update()
    r.scan(T0)
    handed(r)
    r.scan(after(6))
    handed(r)
    r.scan(after(7))
    handed(r)


@case("rules/malware/rescan-changed", "第二轮：改了的、新来的才扫；没变的从记录报；删掉的病毒文件不再报")
def malware_rescan_changed(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    fx.file("~/Downloads/eicar-gone.zip", size=100, at=days(2))
    fx.file("~/Downloads/notes.txt", "just notes\n", at=days(2))
    r.update()
    r.scan(T0)
    handed(r)
    fx.file("~/Downloads/notes.txt", "just notes, and more notes\n", at=after(0.5))
    fx.file("~/Downloads/eicar-fresh.com", size=68, at=after(0.5))
    fx.remove("~/Downloads/eicar-gone.zip")
    r.note("notes.txt 改了，来了 eicar-fresh.com，删了 eicar-gone.zip")
    r.scan(after(1))
    handed(r)


@case("rules/malware/rescan-new-db", "病毒库更新了：3 天内刚来的文件再扫一遍（用新库），早来的从记录报")
def malware_rescan_db(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    fx.file("~/Downloads/eicar-fresh.com", size=68, at=days(1))
    fx.file("~/Downloads/eicar-older.com", size=68, at=days(5))
    r.update()
    r.scan(T0)
    handed(r)
    fx.tool_flag("db-date", "202610210100")
    r.update()
    r.scan(after(1))
    handed(r)


# ---- 坏掉的扫描器

@case("rules/malware/yara-broken", "YARA 跑不起来（退出码 1、没有输出）：报一条「YARA 没扫成」，病毒库照扫；文件不记成扫过，下一轮再扫")
def malware_yara_broken(r: Run) -> None:
    fx = r.fx
    watch_clamscan(fx)
    replace_tool(fx, "yara", '#!/bin/sh\n[ "$1" = "--version" ] && { echo "4.5.2"; exit 0; }\necho "error: could not compile rules" >&2\nexit 1\n')
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    fx.file("~/Downloads/update.scpt", 'display dialog "password" default answer "" with hidden answer', at=days(2))
    r.update()
    r.scan(T0)
    handed(r)
    r.scan(after(1))
    handed(r)


@case("rules/malware/clamscan-broken", "clamscan 自己出错（一个文件都没答、退出码 2）：病毒扫描记成没扫描，写着出错的那一行")
def malware_clamscan_broken(r: Run) -> None:
    fx = r.fx
    replace_tool(fx, "clamscan", '#!/bin/sh\n[ "$1" = "--version" ] && { echo "ClamAV 1.4.3/fixture"; exit 0; }\n'
                                 'echo "LibClamAV Error: cli_loaddbdir(): No supported database files found" >&2\nexit 2\n')
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    r.update()
    r.scan(T0)


@case("rules/malware/clamscan-crash", "clamscan 退出码不是 0、1、2（崩了）：病毒扫描记成没扫描，写着退出码")
def malware_clamscan_crash(r: Run) -> None:
    fx = r.fx
    replace_tool(fx, "clamscan", '#!/bin/sh\n[ "$1" = "--version" ] && { echo "ClamAV 1.4.3/fixture"; exit 0; }\nexit 3\n')
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    r.update()
    r.scan(T0)
