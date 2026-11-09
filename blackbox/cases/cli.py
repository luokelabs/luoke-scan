"""命令行的其余命令：version、用法出错、文字版的 scan/findings/status/report、system、两轮之间看一眼新下载的（--quick）、--if-none。"""
from __future__ import annotations

import datetime

from cases.mcp_tools import small
from cases.rules_apps import blob
from fx import MiB, T0, days, iso
from harness import Run, case


def at(minutes: int) -> datetime.datetime:
    return T0 + datetime.timedelta(minutes=minutes)


@case("cli/version", "版本和规则包的版本")
def version(r: Run) -> None:
    r.cli("version")


@case("cli/usage", "用法出错：没给命令、不认识的命令、少参数、参数配不上、时间写错：退出码 64，说怎么用")
def usage(r: Run) -> None:
    fx = r.fx
    r.cli()
    r.cli("nope")
    r.cli("scan")
    r.cli("scan", "--fixture", fx.root, "--home", fx.home)
    r.cli("scan", "--home", fx.home, "--clock", iso(T0))
    r.cli("scan", "--fixture", fx.root, "--clock", "yesterday")
    r.cli("scan", "--home", fx.home, "--data", fx.data, "--autoclean")
    r.cli("scan", "--fixture", fx.root, "--for-agent", "--autoclean")
    r.cli("findings")
    r.cli("restore", "--fixture", fx.root)
    r.cli("system", "--fixture", fx.root, "--trash", ",")
    r.cli("scan", "--fixture", fx.root, "--bogus")


@case("cli/text", "给人看的文字：查一轮、上一轮的发现、状态（文字和 JSON）、按放心删/要确认/仅供参考分开的报告")
def text(r: Run) -> None:
    small(r, malware=True)
    r.cli("scan", "--fixture", r.fx.root, "--clock", iso(at(10)))
    r.cli("findings", "--data", r.fx.data)
    r.cli("status", "--data", r.fx.data)
    r.cli("status", "--data", r.fx.data, "--json", json_out=True)
    r.cli("report", "--data", r.fx.data)


@case("cli/no-report", "还没查过：findings、status、report 退出码 1，说先查一轮；system 说还没查过")
def no_report(r: Run) -> None:
    r.cli("findings", "--data", r.fx.data)
    r.cli("status", "--data", r.fx.data)
    r.cli("report", "--data", r.fx.data)
    r.cli("system", "--fixture", r.fx.root)


@case("cli/if-none", "--if-none：已经有报告就不查（主控第一次装好时用）；没有就查")
def if_none(r: Run) -> None:
    r.update()
    r.cli("scan", "--fixture", r.fx.root, "--clock", iso(T0), "--if-none")
    r.fx.file("~/Library/Caches/pip/http/blob", size=60 * MiB, at=days(3))
    r.note("pip 的缓存 60 MB")
    r.cli("scan", "--fixture", r.fx.root, "--clock", iso(at(5)), "--if-none")
    r.cli("findings", "--data", r.fx.data)


def system_leftovers(r: Run) -> None:
    """系统的 /Library 里删了的应用留下的（要密码才能移走）：家目录和系统里都有的一个，只在系统里有的一个。查一轮。"""
    fx = r.fx
    sl = "SystemLibrary/"
    blob(fx, sl + "Application Support/io.oldvendor.daemon/state.bin", 2 * MiB)
    blob(fx, sl + "Logs/io.oldvendor.daemon/d.log", 64 * 1024)
    blob(fx, "~/Library/Application Support/io.oldvendor.daemon/prefs.bin", 64 * 1024)
    blob(fx, sl + "Caches/io.sysonly.tool/c.bin", 2 * MiB)
    r.update()
    r.scan(T0)


@case("cli/system", "要密码才能删的：列出来、给编号和命令；假目录里不真要密码，移不了照实说；编号不对的退出码 1")
def system(r: Run) -> None:
    system_leftovers(r)
    r.cli("system", "--fixture", r.fx.root)
    r.cli("system", "--fixture", r.fx.root, "--trash", "a0")
    r.cli("system", "--fixture", r.fx.root, "--trash", "zz9")


@case("cli/quick", "两轮之间看一眼新下载的：用电池、低电量、内存紧张时不看；下载里有新文件才扫，只扫病毒，只换报告里病毒那部分")
def quick(r: Run) -> None:
    small(r)
    fx = r.fx
    r.cli("scan", "--fixture", fx.root, "--clock", iso(at(5)), "--quick")
    fx.file("~/Downloads/eicar-quick.com", size=68, at=at(6))
    r.note("下载里来了一个报毒的文件")
    for key, value, why in (("onBattery", True, "用电池"), ("lowPower", True, "低电量模式"), ("memoryPressure", 4, "内存紧张")):
        fx.fake(key, value)
        r.cli("scan", "--fixture", fx.root, "--clock", iso(at(10)), "--quick", note=why)
        fx.fake(key, {"onBattery": False, "lowPower": False, "memoryPressure": 1}[key])
    r.cli("scan", "--fixture", fx.root, "--clock", iso(at(10)), "--quick", note="接着电源")
    r.cli("findings", "--data", fx.data, "--json", json_out=True)
    r.cli("scan", "--fixture", fx.root, "--clock", iso(at(15)), "--quick", note="没有新的了")
