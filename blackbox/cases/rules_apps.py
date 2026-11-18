"""应用、安装、自己启动的程序、权限这一组规则：残留数据（leftover.app-data）、安装留下的（leftover.installer）、
指向不存在位置的后台任务（persistence.launchagent-missing）、会自己启动的程序（persistence.review）、
别的启动方式（startup）、新装的应用（apps.new）、不在了的应用还拿着的权限（permission.stale-grant）。

每个场景只造它要的那点东西。时钟都不晚于 T0：假目录里没特意设时间的文件夹带着造它的那一刻（真实的时间，比 T0 晚），
时钟早于它，它就永远是「未来」，不会被当成最近写过。
"""
from __future__ import annotations

import datetime
import os
import urllib.parse

from fx import MiB, T0, Fx, days, iso, set_xattr
from harness import Run, case

OLD = days(60)
KiB = 1 << 10


def blob(fx: Fx, rel: str, size: int, at: datetime.datetime = OLD) -> str:
    """一个 size 字节的文件，内容带着自己的路径：两个一样大的不会被当成重复文件。"""
    head = (rel + "\n").encode()
    return fx.file(rel, head + bytes(max(0, size - len(head))), at=at)


def added(fx: Fx, rel: str, at: datetime.datetime) -> None:
    """Spotlight 答的「应用来到文件夹的时间」（fakes.json 的 appsAdded）。"""
    fx.fakes["appsAdded"][fx.p(rel)] = iso(at)


def agent(fx: Fx, name: str, obj: dict, *, binary: bool = False) -> str:
    """家目录里的一个后台任务（~/Library/LaunchAgents/<name>.plist）。"""
    return fx.plist(f"~/Library/LaunchAgents/{name}.plist", obj, at=days(30), binary=binary)


def program(fx: Fx, rel: str, at: datetime.datetime = days(30)) -> str:
    """一个会被后台任务、定时任务运行的程序（只是个小文件；签名看 fakes.json 的 signatures）。"""
    return fx.file(rel, "#!/bin/sh\nexit 0\n", at=at, mode=0o755)


# ================================================================ leftover.app-data：删了的应用留下的数据

@case("rules/leftover.app-data/removed-app", "删了的应用在家目录各处留下的老数据合成一条，要确认；名字前的团队 ID、group. 都认得")
def leftover_removed(r: Run) -> None:
    fx = r.fx
    fx.app("~/Applications/Present.app", "org.present.app", "Present", at=OLD)   # 装着的是别家的，不影响
    lib = "~/Library/"
    for rel, size in [("Application Support/io.gone.editor/db/main.sqlite", 1 * MiB),
                      ("Caches/io.gone.editor/c.bin", 256 * KiB),
                      ("Containers/ABCDE12345.io.gone.editor/Data/x.bin", 256 * KiB),
                      ("Group Containers/ABCDE12345.io.gone.editor/g.bin", 128 * KiB),
                      ("Group Containers/group.io.gone.editor/g.bin", 128 * KiB),
                      ("Saved Application State/io.gone.editor.savedState/window.data", 64 * KiB),
                      ("Logs/io.gone.editor/run.log", 64 * KiB),
                      ("WebKit/io.gone.editor/WebsiteData/x", 64 * KiB)]:
        blob(fx, lib + rel, size)
    blob(fx, lib + "Preferences/io.gone.editor.plist", 4 * KiB)
    blob(fx, lib + "HTTPStorages/io.gone.editor.binarycookies", 4 * KiB)
    for d in ["Application Support/io.gone.editor", "Caches/io.gone.editor", "Containers/ABCDE12345.io.gone.editor",
              "Group Containers/ABCDE12345.io.gone.editor", "Group Containers/group.io.gone.editor",
              "Saved Application State/io.gone.editor.savedState", "Logs/io.gone.editor", "WebKit/io.gone.editor"]:
        fx.age(lib + d, OLD)
    r.update()
    r.scan(T0)


@case("rules/leftover.app-data/not-leftover", "装着的应用（连它的辅助程序、组容器）、还在写的、Apple 和运行时的、不像 bundle id 的、太小的都不算；只报一个真删了的")
def leftover_not(r: Run) -> None:
    fx = r.fx
    fx.app("~/Applications/Present.app", "org.present.app", "Present", at=OLD)
    lib = "~/Library/"
    items = [
        ("Caches/org.present.app", 2 * MiB, OLD),                              # 装着的应用自己的
        ("Application Support/org.present.app.helper", 2 * MiB, OLD),          # 装着的应用的辅助程序（id 以它开头）
        ("Group Containers/group.org.present.app", 2 * MiB, OLD),              # 装着的应用的组容器
        ("Containers/ABCDE12345.org.present.app.share-ext", 2 * MiB, OLD),     # 团队 ID 前缀 + 它的扩展
        ("Caches/com.apple.Music2", 2 * MiB, OLD),                             # Apple 的
        ("Group Containers/group.com.apple.notes", 2 * MiB, OLD),
        ("Application Support/org.python.python", 2 * MiB, OLD),               # 运行时
        ("Caches/com.microsoft.VSCode.ShipIt", 2 * MiB, OLD),
        ("Caches/com.github.Electron.helper", 2 * MiB, OLD),
        ("Application Support/Google", 2 * MiB, OLD),                          # 不像 bundle id
        ("Caches/example.app", 2 * MiB, OLD),                                  # 只有两段
        ("Application Support/io.tiny.tool", 512 * KiB, OLD),                  # 不到 1 MB
        ("Application Support/io.gone.editor", 2 * MiB, OLD),                  # 对照：真删了的
    ]
    for d, size, t in items:
        blob(fx, lib + d + "/data.bin", size, at=t)
        fx.age(lib + d, t)
    # 还在用：同一个应用的一处老了，另一处 3 天前还写过，整个应用都不算残留。
    blob(fx, lib + "Application Support/io.busy.player/library.db", 2 * MiB, at=OLD)
    fx.age(lib + "Application Support/io.busy.player", OLD)
    blob(fx, lib + "Caches/io.busy.player/c.bin", 64 * KiB, at=days(3))
    fx.touch(lib + "Caches/io.busy.player", days(3))
    r.update()
    r.scan(T0)


@case("rules/leftover.app-data/sensitive", "名字像钱包、密码库、验证码、VPN 的：只说不删，标题注明可能有密钥")
def leftover_sensitive(r: Run) -> None:
    fx = r.fx
    lib = "~/Library/"
    for d in ["Application Support/io.parity.ethereum/keys", "Application Support/com.wireguard.macos",
              "Containers/com.twilio.authy/Data", "Application Support/org.keepassxc.keepassxc"]:
        blob(fx, lib + d + "/k.bin", 2 * MiB)
    for d in ["Application Support/io.parity.ethereum", "Application Support/com.wireguard.macos",
              "Containers/com.twilio.authy", "Application Support/org.keepassxc.keepassxc"]:
        fx.age(lib + d, OLD)
    r.update()
    r.scan(T0)


@case("rules/leftover.app-data/same-vendor", "同一家开发商还有应用、安装包、系统后台任务、辅助工具、插件装着：只供参考；只有自己家目录里的后台任务不算")
def leftover_same_vendor(r: Run) -> None:
    fx = r.fx
    fx.app("~/Applications/Studio.app", "net.vendor.studio", "Studio", at=OLD)
    # 系统里装着的组件（假的 /Library、/var/db/receipts）。
    fx.plist("SystemLibrary/LaunchAgents/com.helperco.updater.plist", {"Label": "com.helperco.updater", "ProgramArguments": ["/usr/bin/true"]}, at=OLD)
    fx.file("SystemLibrary/PrivilegedHelperTools/io.toolsmith.helper", "x", at=OLD)
    fx.file("receipts/org.pkgvendor.driver.bom", "x", at=OLD)
    fx.file("receipts/org.pkgvendor.driver.plist", "x", at=OLD)
    fx.plist("SystemLibrary/Application Support/Updaters/Updater.app/Contents/Info.plist", {"CFBundleIdentifier": "dev.updaterco.updater"}, at=OLD)
    fx.plist("SystemLibrary/Audio/Plug-Ins/HAL/Sound.driver/Contents/Info.plist", {"CFBundleIdentifier": "app.soundco.driver"}, at=OLD)
    # 自己家目录里的后台任务：它留下的不能挡住这个应用的数据被提出来。
    agent(fx, "com.selfco.agent", {"Label": "com.selfco.agent", "ProgramArguments": ["/usr/bin/true"]})
    lib = "~/Library/"
    for d in ["Application Support/net.vendor.oldtool", "Caches/com.helperco.sync", "Application Support/io.toolsmith.app",
              "Application Support/org.pkgvendor.panel", "Caches/dev.updaterco.client", "Application Support/app.soundco.mixer",
              "Application Support/com.selfco.app"]:
        blob(fx, lib + d + "/data.bin", 2 * MiB)
        fx.age(lib + d, OLD)
    r.update()
    r.scan(T0)


@case("rules/leftover.app-data/system-library", "系统的 /Library 里删了的应用留下的（要密码才能移走）；macOS 自带的、VPN、装着组件的、后台任务用着的、最近写过的、太小的、链接、Preferences 都不算")
def leftover_system(r: Run) -> None:
    fx = r.fx
    sl = "SystemLibrary/"
    fx.app("~/Applications/Keeper.app", "io.kept.app", "Keeper", at=OLD)
    # 报的：家目录和系统里都有的一个，只在系统里有的一个。
    blob(fx, sl + "Application Support/io.oldvendor.daemon/state.bin", 2 * MiB)
    blob(fx, sl + "Logs/io.oldvendor.daemon/d.log", 64 * KiB)
    blob(fx, "~/Library/Application Support/io.oldvendor.daemon/prefs.bin", 64 * KiB)
    blob(fx, sl + "Caches/io.sysonly.tool/c.bin", 2 * MiB)
    # 不报的。
    for d, size, t in [("Application Support/org.cups.printers", 2 * MiB, OLD),     # macOS 自带的
                       ("Caches/com.apple.example", 2 * MiB, OLD),
                       ("Application Support/com.vpnco.client", 2 * MiB, OLD),      # VPN：系统里的不提
                       ("Caches/io.recent.tool", 2 * MiB, days(2)),                  # 最近写过
                       ("Application Support/io.small.tool", 100 * KiB, OLD),       # 太小
                       ("Application Support/io.kept.app", 2 * MiB, OLD),           # 应用装着
                       ("Application Support/io.jobvendor.data", 2 * MiB, OLD)]:    # 后台任务用着
        blob(fx, sl + d + "/data.bin", size, at=t)
    fx.file(sl + "Application Support/io.jobvendor.data/sync.sh", "#!/bin/sh\n", at=OLD)
    fx.plist(sl + "LaunchDaemons/io.otherco.sync.plist",
             {"Label": "io.otherco.sync", "ProgramArguments": ["/bin/sh", fx.p(sl + "Application Support/io.jobvendor.data/sync.sh")]}, at=OLD)
    blob(fx, sl + "Preferences/io.prefsonly.app.plist", 2 * MiB)                    # Preferences 不在看的地方里
    blob(fx, "elsewhere/linked/data.bin", 2 * MiB)
    fx.age("elsewhere/linked", OLD)
    fx.link(sl + "Caches/io.linked.tool", fx.p("elsewhere/linked"))                  # 链接：不跟过去
    for d in ["Application Support/io.oldvendor.daemon", "Logs/io.oldvendor.daemon", "Caches/io.sysonly.tool",
              "Application Support/org.cups.printers", "Caches/com.apple.example", "Application Support/com.vpnco.client",
              "Application Support/io.small.tool", "Application Support/io.kept.app", "Application Support/io.jobvendor.data"]:
        fx.age(sl + d, OLD)
    fx.touch(sl + "Caches/io.recent.tool", days(2))
    fx.age("~/Library/Application Support/io.oldvendor.daemon", OLD)
    r.update()
    r.scan(T0)


@case("rules/leftover.app-data/no-full-disk-access", "没有完全磁盘访问：别的应用的容器、组容器不列（记成没看全），别处的照报；有了访问再看全")
def leftover_no_access(r: Run) -> None:
    fx = r.fx
    lib = "~/Library/"
    blob(fx, lib + "Containers/io.boxed.app/Data/blob", 2 * MiB)             # 只在容器里
    blob(fx, lib + "Application Support/io.gone.editor/data.bin", 2 * MiB)   # 两处都有
    blob(fx, lib + "Group Containers/ABCDE12345.io.gone.editor/g.bin", 1 * MiB)
    for d in ["Containers/io.boxed.app", "Application Support/io.gone.editor", "Group Containers/ABCDE12345.io.gone.editor"]:
        fx.age(lib + d, OLD)
    r.update()
    r.scan(T0, "--no-full-disk-access")
    r.scan(T0, note="有了完全磁盘访问")


@case("rules/leftover.app-data/rounds", "几轮：一个月内写过的先不算，放够一个月才报；又写了就又不算；装回了应用就不报")
def leftover_rounds(r: Run) -> None:
    fx = r.fx
    lib = "~/Library/"
    blob(fx, lib + "Application Support/io.later.notes/notes.db", 2 * MiB, at=days(45))
    fx.age(lib + "Application Support/io.later.notes", days(45))
    r.update()
    r.scan(days(25), note="T0 前 25 天：数据 20 天前写过")
    r.scan(days(14), note="T0 前 14 天：31 天没写了")
    blob(fx, lib + "Application Support/io.later.notes/new.db", 64 * KiB, at=days(10))
    fx.touch(lib + "Application Support/io.later.notes", days(10))
    r.note("T0 前 10 天又写了一个文件")
    r.scan(days(5), note="T0 前 5 天")
    fx.app("~/Applications/Later.app", "io.later.notes", "Later", at=days(1))
    r.note("装回了这个应用")
    r.scan(T0)


# ================================================================ leftover.installer：安装、升级留下的

@case("rules/leftover.installer/installers", "下载文件夹里两周前来的安装包：认得出是哪个应用、是不是正好是它、版本、是不是下载的；太新、太小、挂着的、不是安装包、链接、应用包里的都不报")
def installers(r: Run) -> None:
    fx = r.fx
    fx.app("~/Applications/Lumen.app", "io.example.lumen", "Lumen", "2.4.1", at=OLD)
    fx.app("~/Applications/Harbor.app", "org.harbor.desktop", "Harbor", "3.0", at=OLD)
    fx.app("~/Applications/Pages.app", "com.apple.iWork.Pages", "Pages", "14.0", at=OLD)
    fx.app("~/Applications/Xcode.app", "com.apple.dt.Xcode", "Xcode", "16.1", at=OLD)
    # 浏览器把网页做成的应用：不是从安装包装的。
    fx.app("~/Applications/Pixelboard.app", "com.google.Chrome.app." + "p" * 32, "Pixelboard", at=OLD,
           extra={"CrAppModeShortcutID": "p" * 32})
    dl = "~/Downloads/"

    def installer(rel: str, *, came: datetime.datetime, size: int = 6 * MiB, by: str = "") -> None:
        blob(fx, dl + rel, size, at=came)
        if by:
            fx.quarantine(dl + rel, by)

    installer("Lumen-2.4.1-arm64.dmg", came=days(40), by="Safari")   # 正好是装着的 Lumen，下载的
    installer("LumenSync-1.2.dmg", came=days(30))                     # 名字以 Lumen 开头，但不是它
    installer("Harbor Setup 3.pkg", came=days(20))
    installer("Pages 14.dmg", came=days(25))                          # Apple 的应用：认得出，但不算正好是它的
    installer("Xcode_16.1.xip", came=days(35))                        # .xip 来的 Apple 应用算
    installer("Pixelboard.dmg", came=days(50))                        # 网页应用：不算正好是它的
    installer("installers/Tool 5.0.mpkg", came=days(16))              # 往下一层也找
    # 不报的。
    installer("fresh.dmg", came=days(3))                              # 才来 3 天
    installer("small.pkg", came=days(40), size=1 * MiB)               # 太小
    installer("Open.dmg", came=days(40))                              # 正挂着
    fx.fake("attachedImages", [fx.p(dl + "Open.dmg")])
    installer("notes.txt", came=days(40))                             # 不是安装包
    fx.link(dl + "link.dmg", fx.p(dl + "Lumen-2.4.1-arm64.dmg"))     # 链接
    installer("Kit.app/Contents/kit.dmg", came=days(40))              # 应用包里的不进去找
    installer("a/b/deep.dmg", came=days(40))                          # 往下两层不找
    for d in ["installers", "Kit.app/Contents", "Kit.app", "a/b", "a"]:
        fx.touch(dl + d, days(40))
    r.update()
    r.scan(T0)


@case("rules/leftover.installer/partial-download", "没下完的下载（.crdownload、.part、Safari 的 .download 文件夹……）一周没动才报；还在下的、太小的、下完了的不报")
def partial_downloads(r: Run) -> None:
    fx = r.fx
    dl = "~/Downloads/"
    blob(fx, dl + "big-video.mp4.crdownload", 2 * MiB, at=days(10))
    blob(fx, dl + "archive.zip.part", 2 * MiB, at=days(8))
    blob(fx, dl + "Movie.mov.download/Movie.mov", 2 * MiB, at=days(9))
    fx.plist(dl + "Movie.mov.download/Info.plist", {"DownloadEntryURL": "https://example.invalid/movie"}, at=days(9))
    fx.touch(dl + "Movie.mov.download", days(9))
    blob(fx, dl + "sub/thing.bin.opdownload", 2 * MiB, at=days(30))
    fx.touch(dl + "sub", days(30))
    # 不报的。
    blob(fx, dl + "live.iso.crdownload", 2 * MiB, at=days(1))         # 还在下
    blob(fx, dl + "tiny.dat.partial", 100 * KiB, at=days(30))         # 太小
    blob(fx, dl + "finished.zip", 2 * MiB, at=days(30))               # 下完了
    blob(fx, dl + "Song.m4a.download/Song.m4a", 2 * MiB, at=days(2))  # Safari 的，里面两天前还在写
    fx.touch(dl + "Song.m4a.download", days(20))
    r.update()
    r.scan(T0)


@case("rules/leftover.installer/relocated-items", "共享文件夹（Shared）里 macOS 升级挪出来的旧配置：只说；别的文件夹、同名的文件不算")
def relocated(r: Run) -> None:
    fx = r.fx
    blob(fx, "Shared/Relocated Items/Configuration/a.conf", 1 * MiB, at=days(200))
    blob(fx, "Shared/Previously Relocated Items 3/Security/b.plist", 2 * MiB, at=days(400))
    fx.age("Shared/Relocated Items", days(200))
    fx.age("Shared/Previously Relocated Items 3", days(400))
    blob(fx, "Shared/Someone Else/c.bin", 1 * MiB)
    blob(fx, "Shared/Previously Relocated Items 2", 1 * MiB)          # 一个文件，不是文件夹
    r.update()
    r.scan(T0)


@case("rules/leftover.installer/no-full-disk-access", "没有完全磁盘访问：下载文件夹里的安装包和没下完的不看（记成没看全），共享文件夹（Shared）里的照报；有了访问再看")
def installers_no_access(r: Run) -> None:
    fx = r.fx
    blob(fx, "~/Downloads/Tool-1.0.dmg", 6 * MiB, at=days(40))
    blob(fx, "~/Downloads/clip.mov.crdownload", 2 * MiB, at=days(10))
    blob(fx, "Shared/Relocated Items/x.conf", 1 * MiB, at=days(200))
    fx.age("Shared/Relocated Items", days(200))
    r.update()
    r.scan(T0, "--no-full-disk-access")
    r.scan(T0, note="有了完全磁盘访问")


def intel_homebrew(fx: Fx, *, apple: bool = True) -> None:
    """/usr/local 里一套 Intel 版的 Homebrew（三个月没动）；apple：旁边 /opt/homebrew 还有一套 Apple 芯片版的。"""
    ul = "usr-local/"
    blob(fx, ul + "Homebrew/bin/brew", 1 * MiB)
    blob(fx, ul + "Homebrew/.git/FETCH_HEAD", 4 * KiB)
    blob(fx, ul + "Cellar/wget/1.0/bin/wget", 2 * MiB)
    blob(fx, ul + "Cellar/python@3.9/3.9.1/bin/python3", 1 * MiB)
    blob(fx, ul + "Cellar/openjdk/21/libexec/openjdk.jdk/Contents/Home/bin/java", 1 * MiB)
    blob(fx, ul + "Caskroom/oldapp/1.0/x", 1 * MiB)
    for d in ["Homebrew", "Cellar", "Caskroom"]:
        fx.age(ul + d, days(90))
    for d in ["Homebrew/.git/FETCH_HEAD", "Homebrew/.git"]:
        fx.touch(ul + d, days(90))
    if apple:
        blob(fx, "opt-homebrew/bin/brew", 64 * KiB)
        blob(fx, "opt-homebrew/Cellar/wget/2.0/bin/wget", 64 * KiB)
        blob(fx, "opt-homebrew/Cellar/openjdk/22/bin/java", 64 * KiB)


@case("rules/leftover.installer/intel-homebrew-only", "Apple 芯片的 Mac 上唯一的一套 Homebrew 是 Intel 版的：只说，不提删；换成 Intel 的 Mac 就不报")
def intel_only(r: Run) -> None:
    intel_homebrew(r.fx, apple=False)
    r.update()
    r.scan(T0)
    r.fx.fake("appleSilicon", False)
    r.scan(T0, note="这是一台 Intel 的 Mac")


@case("rules/leftover.installer/intel-homebrew-unused", "旁边有 Apple 芯片版的、一个月没人用的 Intel 版 Homebrew：提议要密码移到废纸篓，列出只有它装着的")
def intel_unused(r: Run) -> None:
    intel_homebrew(r.fx)
    r.update()
    r.scan(T0)


@case("rules/leftover.installer/intel-homebrew-in-use", "Intel 版 Homebrew 还在用的各种样子：程序正在跑、开机任务、crontab、读不出 crontab、shell 配置、JDK、一个月内 brew update 过；都只说不删")
def intel_in_use(r: Run) -> None:
    fx = r.fx
    intel_homebrew(fx)
    ul = fx.p("usr-local")
    r.update()
    r.scan(T0, note="没人用：提议删")

    fx.fake("running", [ul + "/Cellar/wget/1.0/bin/wget"])
    r.scan(T0, note="它的 wget 正在跑")
    fx.fake("running", [])

    blob(fx, "usr-local/Cellar/redis/7.0/bin/redis-server", 64 * KiB, at=days(90))
    fx.age("usr-local/Cellar", days(90))
    fx.link("usr-local/opt/redis", "../Cellar/redis/7.0")
    agent(fx, "homebrew.mxcl.redis", {"Label": "homebrew.mxcl.redis", "ProgramArguments": [ul + "/opt/redis/bin/redis-server"]})
    r.scan(T0, note="brew services 起的 redis 开机任务用着 /usr/local/opt 里的")
    fx.remove("~/Library/LaunchAgents/homebrew.mxcl.redis.plist")

    fx.fake("crontab", f'0 3 * * * /bin/sh -c "{ul}/opt/wget/bin/wget -q https://example.invalid"\n')
    r.scan(T0, note="crontab 里有一行用着它")
    fx.fake("crontab", None)
    r.scan(T0, note="读不出 crontab")
    fx.fake("crontab", "")

    fx.file("~/.zprofile", f'eval "$({ul}/bin/brew shellenv)"\n', at=days(30))
    r.scan(T0, note="~/.zprofile 里 brew shellenv 用的是它")
    fx.remove("~/.zprofile")

    fx.link("SystemLibrary/Java/JavaVirtualMachines/openjdk.jdk", ul + "/Cellar/openjdk/21/libexec/openjdk.jdk")
    r.scan(T0, note="登记的 JDK 指着它的包")
    fx.remove("SystemLibrary/Java/JavaVirtualMachines/openjdk.jdk")

    fx.touch("usr-local/Homebrew/.git/FETCH_HEAD", days(1))
    r.scan(T0, note="昨天 brew update 过（.git 里的时间也算）")


@case("rules/leftover.installer/intel-homebrew-old-layout", "/usr/local/bin/brew 是老的布局（没有 /usr/local/Homebrew）：只说，说明不是那种布局")
def intel_old_layout(r: Run) -> None:
    fx = r.fx
    blob(fx, "usr-local/bin/brew", 1 * MiB, at=days(90))
    blob(fx, "usr-local/Cellar/wget/1.0/bin/wget", 1 * MiB, at=days(90))
    fx.age("usr-local", days(90))
    blob(fx, "opt-homebrew/bin/brew", 64 * KiB)
    r.update()
    r.scan(T0)


@case("rules/leftover.installer/intel-homebrew-links", "Intel 版 Homebrew 移走以后：还在废纸篓里先不提链接，倒掉了才提失效的链接；放回了、没有它来过的样子都不提")
def intel_links(r: Run) -> None:
    fx = r.fx
    blob(fx, "opt-homebrew/bin/brew", 64 * KiB)
    ul = "usr-local/"
    fx.link(ul + "bin/brew", "../Homebrew/bin/brew")
    fx.link(ul + "bin/wget", "../Cellar/wget/1.0/bin/wget")
    fx.link(ul + "opt/wget", "../Cellar/wget/1.0")
    fx.link(ul + "share/man/man1/brew.1", "../../../Homebrew/manpages/brew.1")
    fx.link(ul + "bin/other", "/nowhere/other")                    # 不是指向 Homebrew 的
    blob(fx, ul + "bin/real-tool", 4 * KiB)
    blob(fx, ul + "lib/libz.dylib", 4 * KiB)
    fx.link(ul + "lib/libfoo.dylib", "libz.dylib")                 # 好的链接
    blob(fx, "Trash/Cellar 2/wget/1.0/bin/wget", 4 * KiB)          # 移进了废纸篓，还能放回
    r.update()
    r.scan(T0, note="Cellar 还在废纸篓里")
    fx.remove("Trash/Cellar 2")
    r.note("倒掉了废纸篓")
    r.scan(T0)
    blob(fx, ul + "Cellar/wget/1.0/bin/wget", 4 * KiB)
    r.note("又把 Cellar 放回了 /usr/local")
    r.scan(T0)
    fx.remove(ul + "Cellar")
    fx.remove(ul + "bin/brew")
    r.note("Cellar 又没了，bin/brew 的链接也删了")
    r.scan(T0)


# ================================================================ persistence.launchagent-missing

@case("rules/persistence.launchagent-missing/missing", "家目录的后台任务指向不存在的程序、参数里的路径、工作目录：报；都在的、系统程序、不是 plist 的不报")
def launchagent_missing(r: Run) -> None:
    fx = r.fx
    gone = fx.p("~/src/removed-checkout")
    agent(fx, "io.example.gone", {"Label": "io.example.gone", "WorkingDirectory": gone,
                                  "ProgramArguments": ["/usr/bin/env", "swift", "run", "--package-path", gone + "/services/x", "x"]})
    agent(fx, "io.example.prog", {"Label": "io.example.prog", "Program": fx.p("~/bin/gone-tool"), "ProgramArguments": ["gone-tool", "--flag"]})
    agent(fx, "nolabel", {"ProgramArguments": [fx.p("~/bin/also-gone")]})                    # 没有 Label：用文件名
    agent(fx, "io.example.binary", {"Label": "io.example.binary", "ProgramArguments": [fx.p("~/bin/third-gone")]}, binary=True)
    agent(fx, "io.example.ok", {"Label": "io.example.ok", "ProgramArguments": ["/bin/ls", "/"]})
    program(fx, "~/bin/present-tool")
    agent(fx, "io.example.present", {"Label": "io.example.present", "ProgramArguments": [fx.p("~/bin/present-tool")],
                                     "WorkingDirectory": fx.p("~/bin")})
    fx.file("~/Library/LaunchAgents/README.txt", "not a job", at=days(30))
    r.update()
    r.scan(T0)


@case("rules/persistence.launchagent-missing/unreadable", "读不出来的 plist（不是 plist、不是字典）：只说读不出来")
def launchagent_unreadable(r: Run) -> None:
    fx = r.fx
    fx.file("~/Library/LaunchAgents/broken.plist", "not a plist", at=days(30))
    fx.plist("~/Library/LaunchAgents/array.plist", ["io.example.array", "/bin/ls"], at=days(30))
    r.update()
    r.scan(T0)


@case("rules/persistence.launchagent-missing/no-full-disk-access", "没有完全磁盘访问：指着文稿里的脚本的不说它不在（不知道），别处不在的照报；有了访问才报文稿里的")
def launchagent_no_access(r: Run) -> None:
    fx = r.fx
    agent(fx, "me.backup", {"Label": "me.backup", "ProgramArguments": ["/bin/zsh", fx.p("~/Documents/scripts/backup.sh")]})
    agent(fx, "me.sync", {"Label": "me.sync", "ProgramArguments": [fx.p("~/bin/sync-gone")]})
    r.update()
    r.scan(T0, "--no-full-disk-access")
    r.scan(T0, note="有了完全磁盘访问")


# ================================================================ persistence.review：会自己启动的程序

SIGS = [{"pathContains": "adhoc", "signature": "adhoc"}, {"pathContains": "invalid", "signature": "invalid"},
        {"pathContains": "script", "signature": "script"}, {"pathContains": "apple", "signature": "apple"},
        {"pathContains": "weird", "signature": "unknown"}, {"pathContains": "unsigned", "signature": "unsigned"}]


@case("rules/persistence.review/signatures", "第一轮：签名对不上的单独报，没人担保的（临时签名、没签名、脚本、没看）合成一条；关掉的、系统的、只写名字的、程序不在的不算；不报新出现的")
def persistence_signatures(r: Run) -> None:
    fx = r.fx
    fx.fake("signatures", SIGS)
    jobs = {"io.example.adhoc": ["adhoc-tool"], "io.example.unsigned": ["unsigned-tool"], "io.example.invalid": ["invalid-tool"],
            "io.example.signed": ["signed-tool"], "io.example.apple": ["apple-tool"], "io.example.weird": ["weird-tool"]}
    for label, (name,) in jobs.items():
        agent(fx, label, {"Label": label, "ProgramArguments": [program(fx, "~/bin/" + name), "--run"]})
    agent(fx, "io.example.script", {"Label": "io.example.script", "ProgramArguments": ["/bin/sh", program(fx, "~/scripts/script-job.sh")]})
    agent(fx, "io.example.off", {"Label": "io.example.off", "ProgramArguments": [program(fx, "~/bin/adhoc-off")], "Disabled": True})
    agent(fx, "io.example.bare", {"Label": "io.example.bare", "ProgramArguments": ["node", "server.js"]})
    agent(fx, "io.example.system", {"Label": "io.example.system", "ProgramArguments": ["/usr/bin/true"]})
    agent(fx, "io.example.missing", {"Label": "io.example.missing", "ProgramArguments": [fx.p("~/bin/adhoc-gone")]})
    r.update()
    r.scan(T0)


@case("rules/persistence.review/new", "之后新出现的、没人担保的后台任务：七天里每轮都报，过了七天不再算新；签名好的不报；签名坏的只按签名报；删了又回来的再报")
def persistence_new(r: Run) -> None:
    fx = r.fx
    fx.fake("signatures", SIGS)
    agent(fx, "io.example.old", {"Label": "io.example.old", "ProgramArguments": [program(fx, "~/bin/adhoc-old")]})
    r.update()
    r.scan(days(12), note="第一轮只记下来")
    adhoc = {"Label": "io.example.fresh", "ProgramArguments": [program(fx, "~/bin/adhoc-fresh")]}
    agent(fx, "io.example.fresh", adhoc)
    agent(fx, "io.example.signed", {"Label": "io.example.signed", "ProgramArguments": [program(fx, "~/bin/signed-new")]})
    agent(fx, "io.example.sneaky", {"Label": "io.example.sneaky", "ProgramArguments": ["/bin/sh", program(fx, "~/.cache/script-sneaky.sh")]})
    agent(fx, "io.example.tampered", {"Label": "io.example.tampered", "ProgramArguments": [program(fx, "~/bin/invalid-new")]})
    r.note("加了四个后台任务：临时签名的、开发者签名的、用 sh 跑的脚本、签名对不上的")
    r.scan(days(11), note="第二天")
    r.scan(days(6), note="又过了五天")
    r.scan(days(3), note="过了八天")
    fx.remove("~/Library/LaunchAgents/io.example.fresh.plist")
    r.note("删了 io.example.fresh")
    r.scan(days(2))
    agent(fx, "io.example.fresh", adhoc)
    r.note("io.example.fresh 又回来了")
    r.scan(days(1))


@case("rules/persistence.review/cron", "crontab：有几行只说；要运行的程序不在了的单独报；之后新加的行报新出现的（找不到程序的不重复报）")
def persistence_cron(r: Run) -> None:
    fx = r.fx
    gone, backup, new = fx.p("~/bin/gone-job"), program(fx, "~/bin/backup"), program(fx, "~/bin/new-job")
    base = f"# 注释\nMAILTO=me@example.invalid\n@reboot {gone}\n0 3 * * * cd /tmp && make\n*/5 * * * * {backup} --quiet\n"
    fx.fake("crontab", base)
    r.update()
    r.scan(days(5), note="第一轮只记下来")
    fx.fake("crontab", base + f"30 2 * * 1 /usr/bin/true\n15 * * * * {new}\n@hourly {fx.p('~/bin/also-gone')}\n")
    r.note("crontab 里加了三行：系统的程序、家目录里的程序、不存在的程序")
    r.scan(days(4))


@case("rules/persistence.review/cron-unreadable", "读不出 crontab 的那一轮沿用上次见过的、说定时任务没查成，读得出了不算新；读出来是空的就忘了，之后再出现就算新")
def persistence_cron_unreadable(r: Run) -> None:
    fx = r.fx
    line = "0 3 * * * /usr/bin/true\n"
    fx.fake("crontab", line)
    r.update()
    r.scan(days(5), note="第一轮只记下来")
    fx.fake("crontab", None)
    r.scan(days(4), note="读不出 crontab")
    fx.fake("crontab", line)
    r.scan(days(3), note="又读得出了")
    fx.fake("crontab", "")
    r.scan(days(2), note="crontab 是空的")
    fx.fake("crontab", line)
    r.scan(days(1), note="那一行又回来了")


@case("rules/persistence.review/path", "shell 启动文件里的 PATH：下载、临时、谁都能写的文件夹和当前文件夹要改，不存在的只说；带别的变量的不猜；没有完全磁盘访问时下载里的照样算，文稿里的不看")
def persistence_path(r: Run) -> None:
    fx = r.fx
    open_dir = fx.dir("open-dir", mode=0o777)
    fx.dir("~/Downloads/bin")
    fx.dir("~/tools/bin")
    fx.dir("~/Documents/bin")
    tmp_bin = fx.dir("$TMPDIR/bin")
    fx.file("~/.zshrc", "\n".join([
        'export PATH="$HOME/Downloads/bin:$HOME/.local/bin:$PATH"',
        "# export PATH=/tmp:$PATH",
        f"path+=({open_dir} ~/no-such-dir)",
        "PATH=$HOME/tools/bin:$GOPATH/bin:$PATH",
        'export PATH="$PATH:"',
    ]) + "\n", at=days(30))
    fx.file("~/.bash_profile", f"export PATH={tmp_bin}:$PATH\nPATH=.:$PATH\n", at=days(30))
    fx.file("~/.profile", 'PATH="$HOME/Documents/bin:$HOME/Documents/missing:$PATH"\n', at=days(30))
    r.update()
    r.scan(T0)
    r.scan(T0, "--no-full-disk-access", note="没有完全磁盘访问")


@case("rules/persistence.review/no-full-disk-access", "没有完全磁盘访问：下载、文稿里的程序不读签名，算没看；新出现的照报但不给路径；有了访问读出签名是好的就不报")
def persistence_no_access(r: Run) -> None:
    fx = r.fx
    fx.fake("signatures", [{"pathContains": "Downloads/helper", "signature": "adhoc"}])
    agent(fx, "io.example.dl", {"Label": "io.example.dl", "ProgramArguments": [program(fx, "~/Downloads/helper")]})
    r.update()
    r.scan(days(5), note="第一轮（有访问）只记下来")
    agent(fx, "io.example.docs", {"Label": "io.example.docs", "ProgramArguments": [program(fx, "~/Documents/tools/sync")]})
    r.note("加了一个运行文稿里的程序的后台任务")
    r.scan(days(4), "--no-full-disk-access", note="没有完全磁盘访问")
    r.scan(days(3), note="有了完全磁盘访问")


# ================================================================ startup：别的启动方式

@case("rules/startup/dyld-insert", "后台任务、应用、shell 启动文件里设的 DYLD_*：注入库的急，改找库地方的次之；注释掉的、别的变量、启动文件里只看 DYLD_INSERT_LIBRARIES")
def startup_dyld(r: Run) -> None:
    fx = r.fx
    tmp = fx.p("$TMPDIR")
    agent(fx, "io.example.inject", {"Label": "io.example.inject", "ProgramArguments": ["/usr/bin/true"],
                                    "EnvironmentVariables": {"DYLD_INSERT_LIBRARIES": tmp + "/x.dylib"}})
    fx.plist("SystemLibrary/LaunchDaemons/io.example.daemon.plist",
             {"Label": "io.example.daemon", "ProgramArguments": ["/usr/bin/true"],
              "EnvironmentVariables": {"DYLD_LIBRARY_PATH": "/opt/lib", "PATH": "/usr/bin"}}, at=days(30))
    fx.plist("SystemLibrary/LaunchAgents/io.example.fw.plist",
             {"Label": "io.example.fw", "ProgramArguments": ["/usr/bin/true"],
              "EnvironmentVariables": {"DYLD_FRAMEWORK_PATH": "/opt/fw", "DYLD_INSERT_LIBRARIES": "/opt/fw/hook.dylib"}}, at=days(30))
    fx.plist("SystemLibrary/LaunchAgents/io.example.fine.plist",
             {"Label": "io.example.fine", "ProgramArguments": ["/usr/bin/true"], "EnvironmentVariables": {"PATH": "/usr/bin"}}, at=days(30))
    fx.app("~/Applications/Odd.app", "io.example.odd", "Odd", at=OLD, extra={"LSEnvironment": {"DYLD_FALLBACK_LIBRARY_PATH": tmp}})
    fx.app("~/Applications/Fine.app", "io.example.fineapp", "Fine", at=OLD, extra={"LSEnvironment": {"LANG": "C"}})
    fx.file("~/.zshrc", "# export DYLD_INSERT_LIBRARIES=/old.dylib\nexport DYLD_INSERT_LIBRARIES=" + tmp + "/hook.dylib\n", at=days(30))
    fx.file("~/.bashrc", "# DYLD_INSERT_LIBRARIES=/x.dylib\nexport DYLD_LIBRARY_PATH=/opt/lib\n", at=days(30))
    fx.file("~/.profile", "DYLD_INSERT_LIBRARIES=/opt/x.dylib some-command\n", at=days(30))
    r.update()
    r.scan(T0)


@case("rules/startup/auth-plugin", "登录窗口的插件（系统的 /Library/Security/SecurityAgentPlugins）：没签名、临时签名、签名坏了的都急；不是 .bundle 的不算")
def startup_auth_plugin(r: Run) -> None:
    fx = r.fx
    base = "SystemLibrary/Security/SecurityAgentPlugins/"
    fx.file(base + "Sneaky.bundle/Contents/Info.plist", "x", at=days(30))
    for name in ["Adhoc", "Tampered"]:
        fx.plist(base + f"{name}.bundle/Contents/Info.plist",
                 {"CFBundleIdentifier": f"io.example.{name.lower()}", "CFBundleExecutable": name, "CFBundlePackageType": "BNDL"}, at=days(30))
        fx.file(base + f"{name}.bundle/Contents/MacOS/{name}", "#!/bin/sh\nexit 0\n", at=days(30), mode=0o755)
        fx.adhoc_sign(base + f"{name}.bundle")
    fx.file(base + "Tampered.bundle/Contents/MacOS/Tampered", "#!/bin/sh\nexit 1\n", at=days(30), mode=0o755)   # 签名以后改过
    fx.file(base + "notes.txt", "x", at=days(30))
    r.update()
    r.scan(T0)


@case("rules/startup/login-hook", "系统偏好里的登录、退出钩子：各报一条；用户自己偏好里的从来不跑，不算；空的不算")
def startup_login_hook(r: Run) -> None:
    fx = r.fx
    lw = "SystemLibrary/Preferences/com.apple.loginwindow.plist"
    fx.plist(lw, {"LoginHook": "/Library/Scripts/.hook.sh", "LogoutHook": "/Library/Scripts/cleanup.sh"}, at=days(30))
    fx.plist("~/Library/Preferences/com.apple.loginwindow.plist", {"LogoutHook": "/tmp/never-runs.sh"}, at=days(30))
    r.update()
    r.scan(T0)
    fx.plist(lw, {"LoginHook": "", "GuestEnabled": False}, at=days(1))
    r.note("系统偏好里的钩子清空了")
    r.scan(T0)


@case("rules/startup/terminal", "终端每开一个窗口先跑的命令（只记程序名）、iTerm2 启动时跑的脚本；清掉以后不报")
def startup_terminal(r: Run) -> None:
    fx = r.fx
    term = "~/Library/Preferences/com.apple.Terminal.plist"
    fx.plist(term, {"Window Settings": {"Basic": {"CommandString": "/usr/local/bin/start --token abc"}, "Pro": {},
                                        "Blank": {"CommandString": "   "},
                                        "Tool": {"CommandString": "TOKEN=abc123 env X=1 helper-cli --serve"}},
                    "Default Window Settings": "Basic"}, at=days(30))
    auto = "~/Library/Application Support/iTerm2/Scripts/AutoLaunch/"
    fx.file(auto + "hello.py", "print(1)\n", at=days(30))
    fx.file(auto + "status_bar.py", "print(2)\n", at=days(30))
    fx.file(auto + ".DS_Store", "x", at=days(30))
    r.update()
    r.scan(T0)
    fx.plist(term, {"Window Settings": {"Basic": {"CommandString": ""}, "Pro": {}}}, at=days(1))
    fx.remove(auto + "hello.py")
    fx.remove(auto + "status_bar.py")
    r.note("终端的命令清掉了，AutoLaunch 里只剩隐藏文件")
    r.scan(T0)


@case("rules/startup/periodic", "系统定时维护里加的本地脚本和改过的设置；只有设置时不写个数；没有 periodic 的系统上不报")
def startup_periodic(r: Run) -> None:
    fx = r.fx
    fx.file("usr-sbin/periodic", "#!/bin/sh\n", at=days(300), mode=0o755)
    fx.file("usr-local/etc/periodic/daily/500.backup", "#!/bin/sh\n", at=days(30), mode=0o755)
    fx.file("usr-local/etc/periodic/weekly/600.report", "#!/bin/sh\n", at=days(30), mode=0o755)
    fx.dir("usr-local/etc/periodic/monthly")
    fx.file("etc/periodic.conf.local", 'daily_output="/var/log/daily.out"\n', at=days(30))
    r.update()
    r.scan(T0)
    fx.remove("usr-local/etc/periodic/daily/500.backup")
    fx.remove("usr-local/etc/periodic/weekly/600.report")
    fx.remove("etc/periodic.conf.local")
    fx.file("etc/periodic.conf", "# changed\n", at=days(10))
    r.note("本地脚本删了，只剩改过的 /etc/periodic.conf")
    r.scan(T0)
    fx.remove("usr-sbin/periodic")
    r.note("系统里没有 periodic 了")
    r.scan(T0)


# ================================================================ apps.new：新装的应用

@case("rules/apps.new/signatures", "最近一个月来的应用：没签名、临时签名、签名坏了的报，带着是谁下载的；往下一层也看；一个月前来的、不知道什么时候来的、往下两层的不看")
def new_apps(r: Run) -> None:
    fx = r.fx
    a = "~/Applications/"
    fx.app(a + "Plain.app", "io.example.plain", "Plain", at=days(2))
    fx.app(a + "Homemade.app", "io.example.homemade", "Homemade", at=days(2))
    fx.adhoc_sign(a + "Homemade.app")
    fx.quarantine(a + "Homemade.app", "Safari")
    fx.app(a + "Broken.app", "io.example.broken", "Broken", at=days(2))
    fx.adhoc_sign(a + "Broken.app")
    fx.file(a + "Broken.app/Contents/MacOS/Broken", "#!/bin/sh\nexit 1\n", at=days(2), mode=0o755)   # 签名以后改过
    fx.app(a + "Utilities/Tool.app", "io.example.tool", "Tool", at=days(2))
    set_xattr(fx.p(a + "Utilities/Tool.app"), "com.apple.quarantine", b"0083;00000000;")   # 有下载标记，没写是谁
    fx.app(a + "Ancient.app", "io.example.ancient", "Ancient", at=days(40))
    fx.app(a + "Unknown.app", "io.example.unknown", "Unknown", at=days(2))              # Spotlight 没答它什么时候来的
    fx.app(a + "Vendor/Sub/Deep.app", "io.example.deep", "Deep", at=days(2))           # 往下两层
    fx.file(a + "readme.txt", "x", at=days(2))
    for rel, t in [("Plain.app", days(2)), ("Homemade.app", days(3)), ("Broken.app", days(1)), ("Utilities/Tool.app", days(5)),
                   ("Ancient.app", days(40)), ("Vendor/Sub/Deep.app", days(2))]:
        added(fx, a + rel, t)
    r.update()
    r.scan(T0)


@case("rules/apps.new/web-app", "浏览器把网页做成的应用（Chrome Apps.localized 里、Chrome 有它的记录、临时签名）不报；只是像的（没有记录、拖到别处的、没签名的）照报")
def new_web_apps(r: Run) -> None:
    fx = r.fx
    pid, other = "p" * 32, "o" * 32
    chrome = fx.p("~/Library/Application Support/Google/Chrome")
    fx.dir("~/Library/Application Support/Google/Chrome/Default/Web Applications/Manifest Resources/" + pid)

    def shim(rel: str, sid: str, *, sign: bool = True) -> None:
        info = {"CFBundleExecutable": "app_mode_loader", "CrAppModeShortcutID": sid, "CrBundleIdentifier": "com.google.Chrome",
                "CFBundleIdentifier": "com.google.Chrome.app." + sid, "CrAppModeUserDataDir": chrome + "/-/Web Applications/_crx_" + sid,
                "CFBundleName": os.path.splitext(os.path.basename(rel))[0]}
        fx.plist("~/Applications/" + rel + "/Contents/Info.plist", info, at=days(1))
        fx.file("~/Applications/" + rel + "/Contents/MacOS/app_mode_loader", "#!/bin/sh\nexit 0\n", at=days(1), mode=0o755)
        if sign:
            fx.adhoc_sign("~/Applications/" + rel)
        added(fx, "~/Applications/" + rel, days(1))

    shim("Chrome Apps.localized/Music.app", pid)                  # 真的网页应用
    shim("Chrome Apps.localized/Fake.app", other)                 # Chrome 没有这个网页应用的记录
    shim("Chrome Apps.localized/Unsigned.app", pid, sign=False)   # 没签名
    shim("Dropped.app", pid)                                      # 一样的东西，拖进了应用文件夹
    r.update()
    r.scan(T0)


@case("rules/apps.new/rounds", "几轮：查过的应用没变照样报；程序被改了再查（签名坏了）；来了超过一个月就不再看")
def new_apps_rounds(r: Run) -> None:
    fx = r.fx
    a = "~/Applications/"
    fx.app(a + "Homemade.app", "io.example.homemade", "Homemade", at=days(35))
    fx.adhoc_sign(a + "Homemade.app")
    added(fx, a + "Homemade.app", days(35))
    fx.app(a + "Plain.app", "io.example.plain", "Plain", at=days(12))
    added(fx, a + "Plain.app", days(12))
    r.update()
    r.scan(days(10), note="T0 前 10 天：Homemade 来了 25 天，Plain 来了 2 天")
    fx.file(a + "Homemade.app/Contents/MacOS/Homemade", "#!/bin/sh\necho patched\n", at=days(8), mode=0o755)
    r.note("Homemade 的主程序被改了")
    r.scan(days(6), note="T0 前 6 天")
    r.scan(T0, note="T0：Homemade 来了 35 天")


# ================================================================ permission.stale-grant：不在了的应用还拿着权限

@case("rules/permission.stale-grant/stale", "不在了的应用、程序还拿着的权限：一个应用的几项合成一条，厉害的（完全磁盘访问、录屏…）中等；装着的、它的辅助程序、程序还在的、拒绝的、不认得的权限不报")
def stale_grants(r: Run) -> None:
    fx = r.fx
    fx.app("~/Applications/Present.app", "org.present.app", "Present", at=OLD)
    present_tool = program(fx, "bin/present-tool")
    fx.tcc([("kTCCServiceSystemPolicyAllFiles", "io.gone.backup", 0, 2),
            ("kTCCServiceCamera", "io.gone.meet", 0, 2),
            ("kTCCServiceMicrophone", "io.gone.meet", 0, 2),
            ("kTCCServiceSystemPolicyDocumentsFolder", "io.gone.docs", 0, 2),
            ("kTCCServiceSystemPolicyDownloadsFolder", "io.gone.docs", 0, 2),
            ("kTCCServiceSystemPolicyDesktopFolder", "io.gone.docs", 0, 2),
            ("kTCCServicePostEvent", "io.gone.remote", 0, 2),
            ("kTCCServiceAppleEvents", "io.gone.remote", 0, 2),
            ("kTCCServiceScreenCapture", fx.p("opt/gone/tool"), 1, 2),
            ("kTCCServiceAccessibility", "org.present.app", 0, 2),          # 装着的
            ("kTCCServiceScreenCapture", "org.present.app.helper", 0, 2),   # 装着的应用的辅助程序
            ("kTCCServiceListenEvent", present_tool, 1, 2),                 # 程序还在
            ("kTCCServiceCamera", "io.gone.denied", 0, 0),                  # 拒绝了的
            ("kTCCServiceAddressBook", "io.gone.crm", 0, 2),
            ("kTCCServiceCalendar", "io.gone.crm", 0, 2),
            ("kTCCServiceBluetoothAlways", "io.gone.bt", 0, 2),
            ("kTCCServiceSystemPolicyAppBundles", "io.gone.updater", 0, 2),  # App 管理：中等
            ("kTCCServiceExampleNotKnown", "io.gone.odd", 0, 2)])            # 不在要说的权限里
    r.update()
    r.scan(T0)


@case("rules/permission.stale-grant/no-full-disk-access", "没有完全磁盘访问：程序在下载里的不去看它在不在，不报；别处不在的照报；有了访问再报")
def stale_grants_no_access(r: Run) -> None:
    fx = r.fx
    fx.tcc([("kTCCServiceAccessibility", fx.p("~/Downloads/gone-helper"), 1, 2),
            ("kTCCServiceScreenCapture", fx.p("opt/gone/tool"), 1, 2)])
    r.update()
    r.scan(T0, "--no-full-disk-access")
    r.scan(T0, note="有了完全磁盘访问")


@case("rules/permission.stale-grant/unreadable", "TCC 的数据库读不了：记成没扫描，说要完全磁盘访问")
def stale_grants_unreadable(r: Run) -> None:
    fx = r.fx
    fx.file(Fx.TCC, "not a database\n", at=days(1))
    r.update()
    r.scan(T0)


APP, AGENT, LOGIN, DAEMON, DEVELOPER, LEGACY = 0x2, 0x8, 0x4, 0x10, 0x20, 0x10000
ON, HIDDEN = 0x3, 0x4    # disposition：开着、允许；不在系统设置里显示


@case("rules/permission.stale-grant/login-items", "已经删掉的应用还在「登录项与扩展」里：应用自己的、里面的后台项、"
      "写明属于它的 launchd 任务（程序还在）；和它的隐私权限合成一条；装着的、挪了地方的、隐藏的、苹果的、在别的盘上的、"
      "开发商那一层、写成文件的老式任务（看文件）、程序已经不在的不报")
def stale_login_items(r: Run) -> None:
    fx = r.fx
    fx.app("~/Applications/Present.app", "org.present.app", "Present", at=OLD)
    apps = "file://" + urllib.parse.quote(fx.p("~/Applications"))
    vpn = program(fx, "opt/gone-vpn/vpn-helper")
    fx.btm([
        # 删掉的同步工具：应用自己、里面的后台项、登录时打开的辅助程序
        {"name": "Gone Sync", "identifier": "2.io.gone.sync", "url": apps + "/Gone%20Sync.app/", "bundleIdentifier": "io.gone.sync",
         "type": APP, "disposition": ON},
        {"name": "Gone Sync Agent", "identifier": "8.io.gone.sync.agent", "container": "2.io.gone.sync",
         "url": "Contents/Library/LaunchAgents/io.gone.sync.agent.plist", "bundleIdentifier": "io.gone.sync.agent",
         "type": AGENT, "disposition": ON},
        {"name": "Gone Sync Helper", "identifier": "4.io.gone.sync.helper", "container": "2.io.gone.sync",
         "url": "Contents/Library/LoginItems/Gone Sync Helper.app", "bundleIdentifier": "io.gone.sync.helper",
         "type": LOGIN, "disposition": ON},
        # 删掉的会议软件：还拿着摄像头，还在登录项里：合成一条
        {"name": "Gone Meet", "identifier": "2.io.gone.meet", "url": apps + "/Gone%20Meet.app/", "bundleIdentifier": "io.gone.meet",
         "type": APP, "disposition": ON},
        # 不报的
        {"name": "Present", "identifier": "2.org.present.app", "url": apps + "/Present.app/", "bundleIdentifier": "org.present.app",
         "type": APP, "disposition": ON},                                                      # 装着
        {"name": "Present", "identifier": "2.org.present.app.old", "url": apps + "/Old/Present.app/",
         "bundleIdentifier": "org.present.app", "type": APP, "disposition": ON},               # 挪了地方
        {"name": "Quiet", "identifier": "2.io.gone.quiet", "url": apps + "/Quiet.app/", "bundleIdentifier": "io.gone.quiet",
         "type": APP, "disposition": ON | HIDDEN},                                             # 隐藏的
        {"name": "Notes", "identifier": "2.com.apple.gone", "url": apps + "/Notes%20Old.app/", "bundleIdentifier": "com.apple.gone",
         "type": APP, "disposition": ON},                                                      # 苹果的
        {"name": "Outside", "identifier": "2.io.gone.outside", "url": "file:///Volumes/Outside/Outside.app/",
         "bundleIdentifier": "io.gone.outside", "type": APP, "disposition": ON},               # 别的盘上
        {"name": "Gone Inc.", "identifier": "Gone Inc.", "type": DEVELOPER, "disposition": ON}, # 开发商那一层
        {"name": "io.gone.vpn.helper", "identifier": "16.io.gone.vpn.helper",
         "url": "file://" + urllib.parse.quote(fx.p("SystemLibrary/LaunchDaemons/io.gone.vpn.helper.plist")),
         "associatedBundleIdentifiers": ["io.gone.vpn"], "type": DAEMON | LEGACY, "disposition": ON},  # 老式的：看文件
        {"name": "Lost", "identifier": "2.io.gone.lost", "container": "2.io.nowhere", "url": "Contents/Library/LoginItems/Lost.app",
         "bundleIdentifier": "io.gone.lost", "type": LOGIN, "disposition": ON},                # 找不到它在哪个应用里
    ])
    fx.tcc([("kTCCServiceCamera", "io.gone.meet", 0, 2)])
    # 写明属于删掉的 VPN 的任务，程序还在：照样以管理员身份启动
    fx.plist("SystemLibrary/LaunchDaemons/io.gone.vpn.helper.plist",
             {"Label": "io.gone.vpn.helper", "Program": vpn, "AssociatedBundleIdentifiers": ["io.gone.vpn"]}, at=OLD)
    # 不报的：属于装着的应用；程序已经不在（别的规则报）；关掉了的
    fx.plist("SystemLibrary/LaunchAgents/org.present.app.agent.plist",
             {"Label": "org.present.app.agent", "Program": program(fx, "opt/present/agent"), "AssociatedBundleIdentifiers": ["org.present.app"]}, at=OLD)
    fx.plist("SystemLibrary/LaunchDaemons/io.gone.nofile.plist",
             {"Label": "io.gone.nofile", "Program": fx.p("opt/gone-nofile/helper"), "AssociatedBundleIdentifiers": "io.gone.nofile"}, at=OLD)
    fx.plist("~/Library/LaunchAgents/io.gone.off.plist",
             {"Label": "io.gone.off", "Program": program(fx, "opt/gone-off/agent"), "AssociatedBundleIdentifiers": ["io.gone.off"],
              "Disabled": True}, at=OLD)
    r.update()
    r.scan(T0)


@case("rules/permission.stale-grant/login-items-unreadable", "「登录项与扩展」的记录读不懂：权限照报，另说结果不完整")
def stale_login_items_unreadable(r: Run) -> None:
    fx = r.fx
    fx.file("backgroundtaskmanagement/BackgroundItems-v16.btm", "not a property list\n", at=days(1))
    fx.file("backgroundtaskmanagement/BackgroundItems-v4.btm", "older, not read\n", at=days(400))
    fx.tcc([("kTCCServiceCamera", "io.gone.meet", 0, 2)])
    r.update()
    r.scan(T0)
