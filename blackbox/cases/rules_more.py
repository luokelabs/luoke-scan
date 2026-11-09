"""要另外几样假答案才走得到的：进程的监听端口和启动参数、系统级的后台任务和登录项、开发者签名、公证。"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from fx import T0, days, iso
from harness import Run, case

ME = os.getuid()


def proc(pid: int, path: str, *, args: Optional[List[str]] = None, listening: Optional[List[tuple]] = None,
         uid: int = ME, ppid: int = 400, started=None) -> Dict[str, Any]:
    p: Dict[str, Any] = {"pid": pid, "ppid": ppid, "uid": uid, "path": path, "started": iso(started or days(1))}
    if args is not None:
        p["arguments"] = args
    if listening is not None:
        p["listening"] = [{"port": port, "address": addr} for port, addr in listening]
    return p


def with_procs(r: Run, *ps: Dict[str, Any]) -> None:
    """加进进程表。程序在假目录里的都建出来（不然又成了「程序被删了」）；父进程是开着的那个应用（不是孤儿）。"""
    for p in ps:
        if p["path"].startswith(r.fx.root) and not os.path.exists(p["path"]):
            r.fx.file(p["path"], "#!/bin/sh\nexit 0\n", mode=0o755)
    r.fx.fake("processes", r.fx.fakes["processes"] + list(ps))


# ================================================================ exposure.listening：在本机以外也能连进来的端口

@case("rules/exposure/listening", "在所有网络上、局域网地址上监听的报；只听本机的、系统的、别的用户的不报；同一个程序几个进程合成一条")
def listening(r: Run) -> None:
    home = r.fx.home
    with_procs(r,
               proc(3001, home + "/.local/bin/devserver", listening=[(3000, "0.0.0.0"), (9229, "127.0.0.1")]),
               proc(3002, home + "/.local/bin/devserver", listening=[(3001, "::")]),          # 同一个程序的另一个进程
               proc(3003, home + "/Applications/Tool.app/Contents/MacOS/Tool", listening=[(8080, "192.168.1.20")]),
               proc(3004, home + "/.local/bin/only-local", listening=[(5432, "127.0.0.1"), (6379, "::1"), (7000, "::ffff:127.0.0.1")]),
               proc(3005, "/usr/libexec/sharingd", listening=[(5000, "0.0.0.0")]),            # macOS 自己的
               proc(3006, home + "/.local/bin/someone-elses", listening=[(4000, "0.0.0.0")], uid=0),
               proc(3007, home + "/.local/bin/quiet"))                                        # 不知道它听什么
    r.update()
    r.scan(T0)


# ================================================================ exposure.argv-secret：命令行里带着的密钥

@case("rules/exposure/argv-secret", "命令行带着密钥的报（只写种类，不写值）；指向文件、变量、问密码的不报；读不到参数的跳过")
def argv_secret(r: Run) -> None:
    home = r.fx.home
    gh = "ghp_" + "EXAMPLE" + "0" * 29
    with_procs(r,
               proc(4001, home + "/.local/bin/deploy", args=["deploy", "--token", gh, "--password=hunter2", "--verbose"]),
               proc(4002, home + "/.local/bin/mysql", args=["mysql", "-uroot", "-pS3cret", "app"]),
               proc(4003, home + "/.local/bin/curl", args=["curl", "-u", "me:pw", "https://example.invalid/api"]),
               proc(4004, home + "/.local/bin/worker", args=["worker", "redis://:pw@cache.example.invalid:6379", "AKIAIOSFODNN7EXAMPLE"]),
               proc(4005, home + "/.local/bin/safe", args=["safe", "--password=$PW", "--private-key", "/keys/deploy", "--token", "@/run/token",
                                                            "--api-key", "-"]),
               proc(4006, home + "/.local/bin/mysql", args=["mysql", "-p", "3306"]),          # 空着的 -p 是问密码
               proc(4007, home + "/.local/bin/curl", args=["curl", "-u", "me", "https://example.invalid"]),
               proc(4008, home + "/.local/bin/unreadable"),                                   # 参数读不到
               proc(4009, "/usr/sbin/sshd", args=["sshd", "--password=x1"]))                   # 系统的不看
    r.update()
    r.scan(T0)


# ================================================================ persistence：假的 /Library 里的后台任务

@case("rules/persistence.review/system-dirs", "所有用户的后台任务、系统后台任务：程序不在了的报；以 root 跑、你自己能改的报高；系统自带的程序不报")
def system_dirs(r: Run) -> None:
    fx = r.fx
    sl = "SystemLibrary/"
    fx.plist(sl + "LaunchAgents/io.example.allusers.plist", {"Label": "io.example.allusers", "ProgramArguments": ["/opt/io-example/gone-agent"]},
             at=days(40))
    fx.plist(sl + "LaunchDaemons/io.example.gonedaemon.plist", {"Label": "io.example.gonedaemon", "Program": "/opt/io-example/gone-daemon"},
             at=days(40))
    fx.file(sl + "Application Support/io.example.tool/helper", "#!/bin/sh\nexit 0\n", mode=0o755, at=days(40))
    fx.plist(sl + "LaunchDaemons/io.example.writable.plist",
             {"Label": "io.example.writable", "ProgramArguments": [fx.p(sl + "Application Support/io.example.tool/helper")]}, at=days(40))
    fx.plist(sl + "LaunchDaemons/io.example.builtin.plist", {"Label": "io.example.builtin", "ProgramArguments": ["/usr/bin/true"]},
             at=days(40))
    r.update()
    r.scan(T0)


# ================================================================ persistence：登录项（launchd 会话里应用登记的）

def services(*rows: tuple) -> str:
    """`launchctl print gui/<uid>` 里 services 那一块：(pid, 状态, 标签)。"""
    body = "".join(f"\t\t{pid}\t{status}\t{label}\n" for pid, status, label in rows)
    return f"gui/{ME} = {{\n\ttype = login\n\tservices = {{\n{body}\t}}\n\tother = 1\n}}\n"


def job(**fields: str) -> str:
    """`launchctl print gui/<uid>/<标签>`：顶层的字段一个制表符，里面的块两个（不算）。"""
    top = "".join(f"\t{k.replace('_', ' ')} = {v}\n" for k, v in fields.items())
    return "io.example = {\n" + top + "\tinherited environment = {\n\t\tpath = /should/not/count\n\t}\n}\n"


def login_setup(r: Run) -> None:
    fx = r.fx
    fx.app("~/Applications/Syncer.app", "io.example.syncer", "Syncer")
    fx.plist("~/Library/LaunchAgents/io.example.fromplist.plist", {"Label": "io.example.fromplist", "ProgramArguments": ["/usr/bin/true"]})
    fx.file("~/.local/bin/unsigned-loader", "#!/bin/sh\nexit 0\n", mode=0o755)
    fx.command("/bin/launchctl", services((501, 0, "io.example.syncer.helper"), ("-", 0, "io.example.loaded"),
                                          ("-", 0, "io.example.fromplist"), (77, 0, "application.com.example.App.1234"),
                                          ("-", 0, "io.example.vanished"), ("-", 0, "io.example.noapp")),
               args=["print", f"gui/{ME}"])
    fx.command("/bin/launchctl", job(path=fx.p("~/Library/BTM/io.example.syncer.helper.plist"), parent_bundle_identifier="io.example.syncer"),
               args=["print", f"gui/{ME}/io.example.syncer.helper"])
    fx.command("/bin/launchctl", job(program=fx.p("~/.local/bin/unsigned-loader")), args=["print", f"gui/{ME}/io.example.loaded"])
    fx.command("/bin/launchctl", "Could not find service", args=["print", f"gui/{ME}/io.example.vanished"], status=113)
    fx.command("/bin/launchctl", job(parent_bundle_identifier="io.example.notinstalled"), args=["print", f"gui/{ME}/io.example.noapp"])


@case("rules/persistence.review/login-items", "launchd 会话里应用登记的后台程序：按登记它的应用找签名；plist 里有的、macOS 的、application.* 不算；说不清的跳过")
def login_items(r: Run) -> None:
    login_setup(r)
    r.update()
    r.scan(T0)


@case("rules/persistence.review/login-items-unknown", "launchctl 有一轮没答复：那一轮说登录项没查成、沿用上次见过的，再答复时不算新出现的")
def login_items_unknown(r: Run) -> None:
    login_setup(r)
    r.update()
    r.scan(days(10))
    gui = next(c for c in r.fx.fakes["commands"] if c["args"] == ["print", f"gui/{ME}"])
    answer = dict(gui)
    gui.update(status=5, output="")
    r.note("launchctl print gui/<uid> 没答复")
    r.scan(days(5))
    gui.update(answer)
    r.note("又答复了")
    r.scan(T0)


# ================================================================ keyboard.watchers：有开发者担保的键盘监听

def tap(program: str, *, all_apps: bool = True, pid: int = 900) -> Dict[str, Any]:
    return {"program": program, "listenOnly": True, "allApps": all_apps, "pid": pid}


@case("rules/keyboard/vouched", "开发者签名的快捷键工具、启动器在看所有按键：合成一条低的、只列名字；没担保的另报")
def keyboard_vouched(r: Run) -> None:
    fx = r.fx
    hot = fx.app("~/Applications/Hotkeys.app", "io.example.hotkeys", "Hotkeys") + "/Contents/MacOS/Hotkeys"
    launcher = fx.app("~/Applications/Launcher.app", "io.example.launcher", "Launcher") + "/Contents/MacOS/Launcher"
    odd = fx.file("~/.local/bin/keyhelper", "#!/bin/sh\nexit 0\n", mode=0o755)
    fx.fake("codesign", {hot: "developer:ABCDE12345", launcher: "developer:FGHIJ67890", odd: "adhoc"})
    fx.fake("eventTaps", [tap(hot, pid=901), tap(hot, pid=902), tap(launcher, pid=903), tap(odd, pid=904)])
    r.update()
    r.scan(T0)


# ================================================================ apps.new：公证

@case("rules/apps.new/trust", "最近装的：苹果的、App Store 的、公证过的不报；只有开发者签名、本机没有公证记录的报低；一个月以前装的不看")
def apps_trust(r: Run) -> None:
    fx = r.fx
    apps = {"Notarized": "notarized", "Store": "appStore", "Apples": "apple", "Devonly": "developer:ABCDE12345", "Olddev": "developer:ABCDE12345"}
    trust, added = {}, {}
    for name, t in apps.items():
        path = fx.app(f"~/Applications/{name}.app", f"io.example.{name.lower()}", name, at=days(5))
        trust[path] = t
        added[path] = iso(days(40) if name == "Olddev" else days(5))
    fx.fake("appTrust", trust)
    fx.fake("appsAdded", added)
    r.update()
    r.scan(T0)


# ================================================================ startup.auth-plugin、browser.native-host：有开发者担保的

@case("rules/startup/auth-plugin-vouched", "登录窗口的插件有开发者签名：照报，但只是低的（公司的单点登录会装）")
def auth_plugin_vouched(r: Run) -> None:
    fx = r.fx
    b = fx.dir("SystemLibrary/Security/SecurityAgentPlugins/ExampleSSO.bundle")
    fx.plist("SystemLibrary/Security/SecurityAgentPlugins/ExampleSSO.bundle/Contents/Info.plist", {"CFBundleIdentifier": "io.example.sso"})
    fx.fake("codesign", {b: "developer:ABCDE12345"})
    r.update()
    r.scan(T0)


@case("rules/browser/native-host-vouched", "浏览器扩展能启动的本机程序有开发者签名：不报")
def native_host_vouched(r: Run) -> None:
    fx = r.fx
    prog = fx.file("~/Applications/Helper.app/Contents/MacOS/host", "#!/bin/sh\nexit 0\n", mode=0o755)
    fx.json("~/Library/Application Support/Google/Chrome/NativeMessagingHosts/io.example.host.json",
            {"name": "io.example.host", "path": prog, "type": "stdio", "allowed_origins": ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]})
    fx.fake("codesign", {prog: "developer:ABCDE12345"})
    r.update()
    r.scan(T0)
