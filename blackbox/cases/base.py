"""基础的假目录：单元测试的 Fixture.build 埋的那些答案（各条规则最常见的情况）放在一起，查两轮。"""
from __future__ import annotations

import datetime

from fx import BROWSER_HELPER, MiB, T0, Fx, days
from harness import Run, case

OLD = days(400)


def build(fx: Fx) -> None:
    """照单元测试的 Fixture.build 摆，只是第一轮之前 pip 的缓存还是空的（单元测试直接往数据库里写了 3 天前是 0）。"""
    # 会重建的缓存：pip 的够大，cargo 的不够。
    fx.dir("~/Library/Caches/pip/http", at=days(3))
    fx.file("~/.cargo/registry/cache/index/x", size=1 * MiB, at=days(3))

    # 每跑一次测试都在临时目录留一份站点构建：25 个不动的 wings-*；同样的样子但正在用的 busy-*；几个普通的。
    for i in range(25):
        d = f"$TMPDIR/wings-A{i:05d}"
        t = days(2 + i % 4)
        fx.file(d + "/index.html", size=5 * MiB, at=t)
        fx.touch(d, t)
    for i in range(25):
        fx.file(f"$TMPDIR/busy-B{i:05d}/x", size=5 * MiB, at=T0)
    for i in range(3):
        fx.file(f"$TMPDIR/misc-C{i:05d}/x", size=1024, at=days(10))

    # 项目。
    p = "~/Projects/"
    fx.repo(p + "old-pushed", remote=True, at=OLD, ignore=["node_modules/", "*.log"])
    fx.file(p + "old-pushed/node_modules/dep/index.js", size=64, at=OLD)
    fx.file(p + "old-pushed/debug.log", size=64, at=OLD)
    fx.repo(p + "old-unpushed", remote=True, at=OLD)
    fx.file(p + "old-unpushed/more.txt", size=100, at=OLD)
    fx.commit(p + "old-unpushed", "local only", at=OLD)
    fx.repo(p + "old-stash", remote=True, at=OLD)
    fx.file(p + "old-stash/README.md", size=4096, at=OLD)
    fx.git(p + "old-stash", "stash", "-q", at=OLD)
    fx.repo(p + "old-noremote", remote=False, at=OLD)
    # 推过了，但被忽略的 .env 只有这里有；被忽略的构建输出不算。
    fx.repo(p + "old-env", remote=True, at=OLD, ignore=[".env", "node_modules/"])
    fx.file(p + "old-env/.env", size=64, at=OLD)
    fx.file(p + "old-env/node_modules/x/index.js", size=64, at=OLD)
    # 仓库自己的配置里写了程序：扫描看的时候 git 不能跑它们。
    fx.repo(p + "old-filter", remote=True, at=OLD)
    fx.git(p + "old-filter", "config", "filter.x.clean", "touch " + fx.p("filter-ran"), at=OLD)
    fx.file("fsmonitor.sh", "#!/bin/sh\ntouch " + fx.p("fsmonitor-ran") + "\n", mode=0o755)
    fx.git(p + "old-env", "config", "core.fsmonitor", fx.p("fsmonitor.sh"), at=OLD)
    fx.repo(p + "recent", remote=True, at=days(5))
    # 一个放了几个仓库的文件夹，其中一个有没推的。
    fx.repo(p + "group/a", remote=True, at=OLD)
    fx.repo(p + "group/b", remote=True, at=OLD)
    fx.file(p + "group/b/wip.txt", size=100, at=OLD)
    fx.commit(p + "group/b", "wip", at=OLD)
    fx.file(p + "group/designs/cover.psd", size=1024, at=OLD)
    # 不在 git 里、一年没动，但解出来的一个文件带着未来的时间。
    fx.file(p + "unpacked/notes.txt", size=2 * MiB, at=OLD)
    fx.file(p + "unpacked/vendor/file.bin", size=100, at=T0 + datetime.timedelta(days=400))
    # 一样老，但太小，不值得提。
    fx.file(p + "tiny/notes.txt", size=100, at=OLD)
    for d in ["old-pushed", "old-unpushed", "old-stash", "old-noremote", "old-env", "old-filter", "group", "tiny"]:
        fx.age(p + d, OLD)
    fx.touch(p + "unpacked/vendor", OLD)
    fx.touch(p + "unpacked", OLD)

    # LaunchAgents：一个指向删掉了的检出，一个没事，一个不是 plist。
    la = "~/Library/LaunchAgents/"
    gone = fx.p("~/.codex/worktrees/c870/tool")
    fx.plist(la + "io.example.gone.plist", {"Label": "io.example.gone", "WorkingDirectory": gone,
                                            "ProgramArguments": ["/usr/bin/env", "swift", "run", "--package-path", gone + "/services/x", "x"]},
             at=days(30))
    fx.plist(la + "io.example.ok.plist", {"Label": "io.example.ok", "ProgramArguments": ["/bin/ls", "/"]}, at=days(30))
    fx.file(la + "broken.plist", "not a plist", at=days(30))

    # 应用：装着一个。残留：一个删了的应用（老数据）、一个还在用的（最近写过）、一个装着的、一个 Apple 的。
    fx.plist("~/Applications/Present.app/Contents/Info.plist", {"CFBundleIdentifier": "org.present.app", "CFBundleName": "Present"})
    fx.file("~/" + BROWSER_HELPER, size=64, at=days(30))
    lib = "~/Library/"
    for rel, size, t in [("Application Support/io.example.removed/data.bin", 2 * MiB, days(60)),
                         ("Preferences/io.example.removed.plist", 4096, days(60)),
                         ("Caches/org.present.app/c.bin", 2 * MiB, days(60)),
                         ("Group Containers/ABCDE12345.io.example.removed/g.bin", 1 * MiB, days(60)),
                         ("Containers/ABCDE12345.io.example.removed/c.bin", 1 * MiB, days(60)),
                         ("Application Support/org.present.oldhelper/h.bin", 2 * MiB, days(60)),
                         ("Application Support/io.parity.ethereum/keys/k.json", 2 * MiB, days(60)),
                         ("Caches/io.example.stillused/c.bin", 2 * MiB, days(1)),
                         ("Caches/com.apple.example/c.bin", 2 * MiB, days(60)),
                         ("Group Containers/group.org.present.app.shared/g.bin", 2 * MiB, days(60))]:
        fx.file(lib + rel, size=size, at=t)
    for d in ["Application Support/io.example.removed", "Caches/org.present.app", "Caches/com.apple.example",
              "Containers/ABCDE12345.io.example.removed", "Application Support/org.present.oldhelper",
              "Application Support/io.parity.ethereum/keys", "Application Support/io.parity.ethereum",
              "Group Containers/group.org.present.app.shared"]:
        fx.touch(lib + d, days(60))

    # TCC：删了的应用有完全磁盘访问，装着的有辅助功能，删了的工具有录屏，一条拒绝的。
    fx.tcc([("kTCCServiceSystemPolicyAllFiles", "io.example.removed", 0, 2),
            ("kTCCServiceAccessibility", "org.present.app", 0, 2),
            ("kTCCServiceScreenCapture", "/opt/gone/tool", 1, 2),
            ("kTCCServiceCamera", "io.example.denied", 0, 0)])

    # 下载：病毒库（假的）认得的一个、假的要密码的脚本、一个太老的。
    fx.file("~/Downloads/eicar-test.com", size=68, at=days(2))
    fx.file("~/Downloads/update.scpt", 'do shell script "x" & (display dialog "macOS needs your password" default answer "" with hidden answer)',
            at=days(1))
    fx.file("~/Downloads/old-eicar.zip", size=100, at=days(100))


@case("base/two-rounds", "基础假目录：3 天前查一轮（pip 的缓存还是空的），pip 长到 60 MB 以后再查一轮", quiet=False)
def two_rounds(r: Run) -> None:
    fx = r.fx
    build(fx)
    r.update()
    r.scan(days(3), note="3 天前：pip 的缓存还是空的")
    fx.file("~/Library/Caches/pip/http/blob", size=60 * MiB, at=days(0.5))
    r.note("pip 的缓存长到 60 MB")
    r.scan(T0)


@case("base/empty", "空的家目录、没毛病的 Mac：一条发现都没有")
def empty(r: Run) -> None:
    r.update()
    r.scan(T0)
