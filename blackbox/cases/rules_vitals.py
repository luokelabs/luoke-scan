"""运行状况（luoke-scan#126）：一直占满处理器的后台程序、内存吃紧、电池老化、发热。都从假答案 `vitals` 来，
进程是假进程表里的（当前用户的才看）。"""
from __future__ import annotations

import datetime
from typing import Any, Dict

from agent import Agent
from cases.rules_more import proc, with_procs
from fx import T0
from harness import Run, case

GiB = 1024 ** 3
MiB = 1024 ** 2


def hours(h: float) -> datetime.datetime:
    return T0 - datetime.timedelta(hours=h)


def vitals(r: Run, **change: Any) -> None:
    v: Dict[str, Any] = dict(r.fx.fakes["vitals"])
    v.update(change)
    r.fx.fake("vitals", v)


def busy(total: float, now: float, seconds: float = 3) -> list:
    """两次读数：到后一次一共用了 total 秒处理器，这 seconds 秒里占一个核的 now。"""
    return [round(total - now * seconds, 3), total]


def page(r: Run, label: str = "", event: str = "scan_open_settings") -> None:
    """扫描页上这一项的样子，点它的按钮。"""
    a = Agent(r, T0 + datetime.timedelta(minutes=1))
    a.read("page/overview")
    a.read("summary")
    if label:
        a.click(event, label, page="overview")


@case("rules/vitals/healthy", "运行正常的笔记本：电池 300 次、容量 95%，内存压力正常，不热，没有占满处理器的：什么都不报")
def healthy(r: Run) -> None:
    vitals(r, battery={"cycles": 300, "designCycles": 1000, "capacity": 4750, "designCapacity": 5000}, swap=200 * MiB)
    r.update()
    r.scan(T0)


@case("rules/vitals/cpu-stuck", "后台的同步助手 3 小时一直占满一个核：报，按钮打开活动监视器；刚起来的、平均不高的、别的用户的、扫描自己的工具不报")
def cpu_stuck(r: Run) -> None:
    home = r.fx.home
    sync = home + "/.local/opt/SyncHelper.app/Contents/MacOS/SyncHelper"
    with_procs(r,
               proc(4001, sync, started=hours(3)),
               proc(4002, home + "/.local/bin/just-started", started=hours(0.1)),        # 10 分钟：还不算一直
               proc(4003, home + "/.local/opt/Browser2.app/Contents/MacOS/Browser2", started=hours(120)),  # 5 天平均 20%
               proc(4004, "/usr/sbin/someone-elses", started=hours(10), uid=0),           # 别的用户的
               proc(4005, home + "/.local/bin/clamscan", started=hours(2)))              # 扫描自己起的工具
    vitals(r, cpu={"4001": busy(0.95 * 3 * 3600, 0.99), "4002": busy(500, 1.0), "4003": busy(0.2 * 120 * 3600, 1.0),
                   "4004": busy(0.99 * 10 * 3600, 1.0), "4005": busy(0.99 * 2 * 3600, 1.0)})
    r.update()
    r.scan(T0)
    page(r, "在活动监视器里看")


@case("rules/vitals/cpu-since-last-round", "跑了好几天、平均不高的程序：这一轮起比上一轮一直占满（隔了 1 小时）才报")
def cpu_since_last(r: Run) -> None:
    app = r.fx.home + "/.local/opt/Indexer.app/Contents/MacOS/Indexer"
    with_procs(r, proc(4101, app, started=hours(24 * 5)))
    base = 0.1 * 5 * 24 * 3600
    vitals(r, cpu={"4101": busy(base, 1.0)})
    r.update()
    r.scan(T0 - datetime.timedelta(hours=1), note="上一轮：这会儿忙，但 5 天平均才 10%")
    vitals(r, cpu={"4101": busy(base + 0.97 * 3600, 1.0)})
    r.scan(T0, note="这一轮：比上一轮多用了 0.97 小时的处理器")


@case("rules/vitals/memory-tight", "内存压力警告、交换空间用了 3 GB：报内存不够，点名占得最多的（同一个应用的进程加在一起）")
def memory_tight(r: Run) -> None:
    home = r.fx.home
    chrome = home + "/.local/opt/Google Chrome.app/Contents/MacOS/Google Chrome"
    helper = home + "/.local/opt/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)"
    slack = home + "/.local/opt/Slack.app/Contents/MacOS/Slack"
    with_procs(r, proc(4201, chrome), proc(4202, helper, ppid=4201), proc(4203, helper, ppid=4201), proc(4204, slack),
               proc(4205, home + "/.local/bin/small-tool"))
    vitals(r, pressure=2, swap=3 * GiB,
           footprint={"4201": 1 * GiB, "4202": 3 * GiB, "4203": 2 * GiB, "4204": 1200 * MiB, "4205": 80 * MiB})
    r.update()
    r.scan(T0)
    page(r, "在活动监视器里看")


@case("rules/vitals/memory-engine", "内存不够用、占得最多的是螺壳主控装的模型引擎：照样报内存不够，不点它的名字，点名其余的；"
      "用户自己装在「应用程序」里的 oMLX 照样点名")
def memory_engine(r: Run) -> None:
    home = r.fx.home
    engine = home + "/Library/Application Support/luoke-core/engines/omlx-0.7.3/oMLX.app/Contents/MacOS/oMLX"
    worker = home + "/Library/Application Support/luoke-core/engines/omlx-0.7.3/oMLX.app/Contents/Resources/python/bin/python3"
    slack = home + "/.local/opt/Slack.app/Contents/MacOS/Slack"
    with_procs(r, proc(4301, engine), proc(4302, worker, ppid=4301), proc(4303, slack))
    vitals(r, pressure=2, swap=3 * GiB, footprint={"4301": 6800 * MiB, "4302": 900 * MiB, "4303": 1200 * MiB})
    r.update()
    r.scan(T0)
    page(r)
    # 用户自己装的 oMLX（不在主控的环境目录里）：是用户认得的应用，照样点名
    mine = home + "/Applications/oMLX.app/Contents/MacOS/oMLX"
    with_procs(r, proc(4311, mine), proc(4312, slack))
    vitals(r, pressure=2, swap=3 * GiB, footprint={"4311": 5 * GiB, "4312": 1200 * MiB})
    r.scan(T0 + datetime.timedelta(minutes=2))


@case("rules/vitals/busy-engine", "螺壳主控装的模型引擎 3 小时一直占满两个核、发热时最忙也是它：不报它卡住了，发热照样报、点名其余最忙的；"
      "用户自己装在「应用程序」里的 oMLX 一直占满照样报")
def busy_engine(r: Run) -> None:
    home = r.fx.home
    engine = home + "/Library/Application Support/luoke-core/engines/omlx-0.7.3/oMLX.app/Contents/MacOS/oMLX"
    app = home + "/.local/opt/Renderer.app/Contents/MacOS/Renderer"
    with_procs(r, proc(4401, engine, started=hours(3)), proc(4402, app, started=hours(0.2)))
    vitals(r, thermal=[2, 3], cpu={"4401": busy(1.9 * 3 * 3600, 2.0), "4402": busy(500, 0.8)})
    r.update()
    r.scan(T0)
    page(r, "在活动监视器里看")
    # 用户自己装的 oMLX（不在主控的环境目录里）：是用户认得的应用，照样报
    mine = home + "/Applications/oMLX.app/Contents/MacOS/oMLX"
    with_procs(r, proc(4411, mine, started=hours(3)))
    vitals(r, thermal=[2, 3], cpu={"4411": busy(1.9 * 3 * 3600, 2.0)})
    r.scan(T0 + datetime.timedelta(minutes=2))


@case("rules/vitals/memory-edges","压力警告但几乎没用交换空间：不报；压力严重：不看交换空间也报；压力正常、交换空间很大：不报")
def memory_edges(r: Run) -> None:
    vitals(r, pressure=2, swap=200 * MiB)
    r.update()
    r.scan(T0)
    vitals(r, pressure=4, swap=0)
    r.scan(T0 + datetime.timedelta(minutes=1))
    vitals(r, pressure=1, swap=8 * GiB)
    r.scan(T0 + datetime.timedelta(minutes=2))


@case("rules/vitals/battery-worn", "电池只剩新电池的 72%：报，按钮打开「电池」设置")
def battery_worn(r: Run) -> None:
    vitals(r, battery={"cycles": 640, "designCycles": 1000, "capacity": 3600, "designCapacity": 5000})
    r.update()
    r.scan(T0)
    page(r, "打开「电池」设置")


@case("rules/vitals/battery-cycles", "电池充放电 1050 次，过了设计的 1000 次（容量还有 85%）：报；没写设计次数的按 1000 算；正好 80% 不报")
def battery_cycles(r: Run) -> None:
    vitals(r, battery={"cycles": 1050, "designCycles": 1000, "capacity": 4250, "designCapacity": 5000})
    r.update()
    r.scan(T0)
    vitals(r, battery={"cycles": 1000, "designCycles": 0, "capacity": 4000, "designCapacity": 5000})
    r.scan(T0 + datetime.timedelta(minutes=1))
    vitals(r, battery={"cycles": 999, "designCycles": 0, "capacity": 4000, "designCapacity": 5000})
    r.scan(T0 + datetime.timedelta(minutes=2))


@case("rules/vitals/thermal", "两次读到的发热档位都在「重」以上：报，说出最忙的程序；只有一次高：不报")
def thermal(r: Run) -> None:
    app = r.fx.home + "/.local/opt/Renderer.app/Contents/MacOS/Renderer"
    with_procs(r, proc(4301, app, started=hours(0.2)))
    vitals(r, thermal=[2, 3], cpu={"4301": busy(700, 2.4)})
    r.update()
    r.scan(T0)
    page(r, "在活动监视器里看")
    vitals(r, thermal=[2, 1])
    r.scan(T0 + datetime.timedelta(minutes=5))


@case("rules/vitals/unreadable", "什么都读不到：这一项没查成；只有一部分读不到：照报读到的，另记一条哪几样没读到")
def unreadable(r: Run) -> None:
    vitals(r, cpu=None, pressure=0, swap=None, batteryUnknown=True, thermal=[])
    r.update()
    r.scan(T0)
    vitals(r, cpu={}, pressure=4, swap=None, batteryUnknown=True, thermal=[])
    r.scan(T0 + datetime.timedelta(minutes=1))
