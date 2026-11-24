"""空间这一组的规则：可用空间（space.low）、哪里在涨（space）、系统层的空间（space.system）、重复文件（space.duplicates）、
会重建的缓存（cache.rebuildable）、临时目录里没删的（leak.temp-prefix）、老项目（stale.project）、很久没打开的大文件
（stale.large-file）。

假目录模式只调低了三处门槛（README）：每天涨 1 MiB 就算在涨，重复文件、很久没打开的大文件 1 MiB 起。别的和真机一样：
缓存 50 MiB、临时目录一组 100 MiB、能重新生成的 100 MiB、虚拟磁盘 5 GiB、一个模型 2 GiB……这些大的用 APFS 克隆凑
（`bulk`）：真写的只有一块，别的都是它的克隆，量出来的（分配的）大小照算，磁盘上不多占。

在文件夹里新建东西，会把文件夹的修改时间改成真的现在（比假目录的时钟晚）。看「最近动过没有」的规则（老项目、临时目录、
设备支持文件、模型）的场景，东西摆好以后都把时间重新设一遍，免得结果跟着跑的那天变。
"""
from __future__ import annotations

import ctypes
import ctypes.util
import datetime
import os
from typing import Callable, List, Optional, Union

from fx import MiB, T0, Fx, days, iso, set_times
from harness import Run, case

KiB = 1 << 10
GiB = 1 << 30
TiB = 1 << 40
OLD = days(400)
NO_FDA = "--no-full-disk-access"

# ---------------------------------------------------------------- 帮手

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def clone(fx: Fx, src: str, dst: str, *, at: Optional[datetime.datetime] = None) -> str:
    """dst 做成 src 的 APFS 克隆（两份共用一份数据）；时间设成 at（默认 T0）。路径写法同 fx。"""
    s, d = fx.p(src), fx.p(dst)
    os.makedirs(os.path.dirname(d), exist_ok=True)
    if _libc.clonefile(s.encode(), d.encode(), 0) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e), d)
    set_times(d, at or T0)
    return d


def _seed(fx: Fx, chunk: int) -> str:
    """克隆的底：在假目录外面（扫描不看的地方）真写一块 chunk 字节的。"""
    path = os.path.join(os.path.dirname(fx.root), "blocks", f"seed-{chunk}.bin")
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(bytes(chunk))
    return path


def bulk(fx: Fx, rel: str, size: int, *, at: Optional[datetime.datetime] = None, chunk: int = 64 * MiB) -> str:
    """rel 文件夹里放 size 字节：若干个 chunk 大的克隆，零头真写一个。文件和这个文件夹本身的时间都设成 at（默认 T0）。"""
    d = fx.dir(rel)
    n, rest = divmod(size, chunk)
    for i in range(n):
        clone(fx, _seed(fx, chunk), os.path.join(d, f"part-{i:04d}.bin"), at=at)
    if rest:
        fx.file(os.path.join(d, f"part-{n:04d}.bin"), size=rest, at=at)
    set_times(d, at or T0)
    return d


def disk(r: Run, free: int, total: int, swap: Optional[int] = None) -> None:
    """家目录所在的盘：可用、总量、交换文件用了多少（字节）。"""
    r.fx.fake("volume", {"free": free, "total": total, "swap": swap})


def spotlit(r: Run, rel: str, *, used: Optional[datetime.datetime] = None, changed: Optional[datetime.datetime] = None) -> None:
    """Spotlight 答「很久没用」的一个文件：上次打开、上次修改（None：Spotlight 没记）。"""
    r.fx.fakes["staleFiles"].append({"path": r.fx.p(rel), "used": used and iso(used), "changed": changed and iso(changed)})


When = Union[datetime.datetime, Callable[[int], datetime.datetime]]


def temp_group(fx: Fx, prefix: str, n: int, size: int, *, at: When, first: int = 0) -> None:
    """临时目录里 n 个 <prefix>-A0000i 文件夹，各放一个 size 字节的文件（克隆，不多占磁盘），最后动过的时间 at（或 at(i)）。"""
    for i in range(first, first + n):
        t = at(i) if callable(at) else at
        d = f"$TMPDIR/{prefix}-A{i:05d}"
        clone(fx, _seed(fx, size), d + "/index.html", at=t)
        fx.touch(d, t)


def model(fx: Fx, rel: str, size: int, at: datetime.datetime) -> None:
    """一个模型的文件夹（数据在它的 blobs 里），文件夹的时间是下载的时间。"""
    bulk(fx, rel + "/blobs", size, at=at)
    fx.touch(rel, at)


# ================================================================ space.low：可用空间

@case("rules/space.low/low", "盘 100 GiB、只剩 15 GiB（门槛 20 GiB）：报，带上交换文件用了多少")
def low_low(r: Run) -> None:
    disk(r, 15 * GiB, 100 * GiB, swap=3 * GiB)
    r.update()
    r.scan(T0)


@case("rules/space.low/no-swap", "空间不够，但不知道交换文件多大：照报，证据里没有 swap")
def low_no_swap(r: Run) -> None:
    disk(r, 15 * GiB, 100 * GiB)
    r.update()
    r.scan(T0)


@case("rules/space.low/at-threshold", "可用的正好 20 GiB：不报（比门槛少才报）")
def low_at_threshold(r: Run) -> None:
    disk(r, 20 * GiB, 100 * GiB, swap=1 * GiB)
    r.update()
    r.scan(T0)


@case("rules/space.low/just-under", "可用的比 20 GiB 少 1 字节：报")
def low_just_under(r: Run) -> None:
    disk(r, 20 * GiB - 1, 100 * GiB, swap=1 * GiB)
    r.update()
    r.scan(T0)


@case("rules/space.low/big-disk", "盘 2 TiB：门槛是总量的一成（约 205 GiB），剩 150 GiB 也报")
def low_big_disk(r: Run) -> None:
    disk(r, 150 * GiB, 2 * TiB, swap=0)
    r.update()
    r.scan(T0)


@case("rules/space.low/big-disk-plenty", "盘 2 TiB、剩 250 GiB：超过一成，不报")
def low_big_disk_plenty(r: Run) -> None:
    disk(r, 250 * GiB, 2 * TiB, swap=0)
    r.update()
    r.scan(T0)


@case("rules/space.low/unknown", "不知道家目录所在的盘多大（volume 是 null）：不报")
def low_unknown(r: Run) -> None:
    r.fx.fake("volume", None)
    r.update()
    r.scan(T0)


@case("rules/space.low/zero-total", "盘的总量读成 0：不报")
def low_zero_total(r: Run) -> None:
    disk(r, 0, 0)
    r.update()
    r.scan(T0)


# ================================================================ space：哪里在涨（看这一轮和前 7 天里最早那次的差）

LOG = "~/Library/Logs/Tool/run.log"   # ~/Library/Logs 整个算一处


@case("rules/space/growth", "~/Library/Logs 一周从 4 MiB 涨到 18 MiB（每天 2 MiB）：报在涨")
def space_growth(r: Run) -> None:
    r.fx.file(LOG, size=4 * MiB, at=days(7))
    r.update()
    r.scan(days(7), note="一周前：4 MiB")
    r.fx.file(LOG, size=18 * MiB, at=days(1))
    r.note("run.log 长到 18 MiB")
    r.scan(T0)


@case("rules/space/exactly-threshold", "一周正好涨 7 MiB（每天正好 1 MiB）：报")
def space_exactly(r: Run) -> None:
    r.fx.file(LOG, size=4 * MiB, at=days(7))
    r.update()
    r.scan(days(7))
    r.fx.file(LOG, size=11 * MiB, at=days(1))
    r.note("run.log 长了 7 MiB")
    r.scan(T0)


@case("rules/space/just-under", "一周涨 7 MiB 差 4 KiB（每天不到 1 MiB）：不报")
def space_just_under(r: Run) -> None:
    r.fx.file(LOG, size=4 * MiB, at=days(7))
    r.update()
    r.scan(days(7))
    r.fx.file(LOG, size=11 * MiB - 4 * KiB, at=days(1))
    r.note("run.log 长了 7 MiB - 4 KiB")
    r.scan(T0)


@case("rules/space/two-days", "两天前量过一次，这两天涨了 6 MiB：报每天 3 MiB")
def space_two_days(r: Run) -> None:
    r.fx.file(LOG, size=4 * MiB, at=days(2))
    r.update()
    r.scan(days(2))
    r.fx.file(LOG, size=10 * MiB, at=days(1))
    r.note("run.log 长了 6 MiB")
    r.scan(T0)


@case("rules/space/baseline-too-old", "上次量是 8 天前（超出 7 天）：涨得再多也没有可比的，不报")
def space_too_old(r: Run) -> None:
    r.fx.file(LOG, size=4 * MiB, at=days(8))
    r.update()
    r.scan(days(8))
    r.fx.file(LOG, size=40 * MiB, at=days(1))
    r.note("run.log 长到 40 MiB")
    r.scan(T0)


@case("rules/space/same-day", "同一天里量了两次、中间涨了 30 MiB：只和前几天比，不报")
def space_same_day(r: Run) -> None:
    r.fx.file(LOG, size=4 * MiB, at=T0 - datetime.timedelta(hours=6))
    r.update()
    r.scan(T0 - datetime.timedelta(hours=6), note="当天早些时候")
    r.fx.file(LOG, size=34 * MiB, at=T0 - datetime.timedelta(hours=1))
    r.note("run.log 长到 34 MiB")
    r.scan(T0)


@case("rules/space/oldest-in-window", "7 天前 4 MiB、4 天前 18 MiB、今天没变：今天也报（和 7 天里最早的那次比，每天 2 MiB）")
def space_oldest_in_window(r: Run) -> None:
    r.fx.file(LOG, size=4 * MiB, at=days(7))
    r.update()
    r.scan(days(7))
    r.fx.file(LOG, size=18 * MiB, at=days(4.5))
    r.note("run.log 长到 18 MiB")
    r.scan(days(4))
    r.note("之后没再变")
    r.scan(T0)


@case("rules/space/shrink", "一周里从 30 MiB 变成 10 MiB：变小不报")
def space_shrink(r: Run) -> None:
    r.fx.file(LOG, size=30 * MiB, at=days(7))
    r.update()
    r.scan(days(7))
    r.fx.file(LOG, size=10 * MiB, at=days(1))
    r.note("run.log 剩 10 MiB")
    r.scan(T0)


@case("rules/space/new-folder", "上一轮还没有的文件夹，这一轮 30 MiB：没有以前的大小可比，不报")
def space_new_folder(r: Run) -> None:
    r.update()
    r.scan(days(7))
    r.fx.file(LOG, size=30 * MiB, at=days(1))
    r.note("新建 ~/Library/Logs，放进 30 MiB")
    r.scan(T0)


@case("rules/space/tmp", "临时目录一周涨了 21 MiB：报在临时目录上")
def space_tmp(r: Run) -> None:
    r.fx.file("$TMPDIR/build/out.bin", size=1 * MiB, at=days(7))
    r.update()
    r.scan(days(7))
    r.fx.file("$TMPDIR/build/out.bin", size=22 * MiB, at=days(1))
    r.note("$TMPDIR/build/out.bin 长到 22 MiB")
    r.scan(T0)


# 拆开量的：家目录下每一项各算一处，Library、.cache、.local 再往下拆一层，Library 的 Caches、Application Support、
# Containers、Developer 再拆一层。每处一周涨 7×N MiB（每天 N MiB）。
SPLIT = [("~/Library/Caches/SomeTool", 2), ("~/Library/Application Support/SomeTool", 3), ("~/Library/Containers/SomeBox", 4),
         ("~/Library/Developer/Toolchains", 5), ("~/Library/Group Containers/SomeGroup", 6), ("~/.cache/sometool", 7),
         ("~/.local/share/sometool", 8), ("~/.local/bin", 9), ("~/VMs/disk", 10)]


@case("rules/space/split-folders", "Library、.cache、.local 拆开量：每处报在自己那一层（Group Containers 整个算一处）")
def space_split(r: Run) -> None:
    fx = r.fx
    for rel, _ in SPLIT:
        fx.file(rel + "/a.bin", size=1 * MiB, at=days(7))
    r.update()
    r.scan(days(7))
    for rel, n in SPLIT:
        bulk(fx, rel + "/new", n * 7 * MiB, at=days(1), chunk=7 * MiB)
    r.note("每处各涨 7×N MiB：" + "、".join(f"{rel} {n * 7} MiB" for rel, n in SPLIT))
    r.scan(T0)


@case("rules/space/not-watched", "废纸篓、CloudStorage、指到家目录外的链接、直接放在家目录和 Caches 里的文件：涨了也不报")
def space_not_watched(r: Run) -> None:
    fx = r.fx
    fx.file("~/.Trash/a.bin", size=1 * MiB, at=days(7))
    fx.file("~/Library/CloudStorage/SomeDrive/a.bin", size=1 * MiB, at=days(7))
    fx.file("elsewhere/a.bin", size=1 * MiB, at=days(7))
    fx.link("~/Linked", fx.p("elsewhere"))
    r.update()
    r.scan(days(7))
    for rel in ["~/.Trash/new", "~/Library/CloudStorage/SomeDrive/new", "elsewhere/new"]:
        bulk(fx, rel, 14 * MiB, at=days(1), chunk=7 * MiB)
    clone(fx, _seed(fx, 7 * MiB), "~/loose.bin", at=days(1))
    clone(fx, _seed(fx, 7 * MiB), "~/Library/Caches/loose.bin", at=days(1))
    r.note("废纸篓、CloudStorage、链接指向的文件夹各涨 14 MiB；家目录和 ~/Library/Caches 里直接多了一个 7 MiB 的文件")
    r.scan(T0)


@case("rules/space/no-full-disk-access", "没有完全磁盘访问：下载和容器不量（记成没看全），别处的照报；有了访问再和一周前比")
def space_no_fda(r: Run) -> None:
    fx = r.fx
    fx.file(LOG, size=4 * MiB, at=days(7))
    fx.file("~/Downloads/a.bin", size=1 * MiB, at=days(7))
    fx.file("~/Library/Containers/SomeBox/Data/a.bin", size=1 * MiB, at=days(7))
    r.update()
    r.scan(days(7), note="一周前，有完全磁盘访问")
    fx.file(LOG, size=18 * MiB, at=days(1))
    fx.file("~/Downloads/a.bin", size=15 * MiB, at=days(1))
    fx.file("~/Library/Containers/SomeBox/Data/a.bin", size=15 * MiB, at=days(1))
    r.note("三处各涨 14 MiB")
    r.scan(T0, NO_FDA, note="没有完全磁盘访问")
    r.note("同一天里又有了完全磁盘访问")
    r.scan(T0)


@case("rules/space/no-full-disk-access-unguarded", "没有完全磁盘访问、家目录里也没有受保护的文件夹：照常报涨，不记没看全")
def space_no_fda_unguarded(r: Run) -> None:
    r.fx.file(LOG, size=4 * MiB, at=days(7))
    r.update()
    r.scan(days(7), NO_FDA)
    r.fx.file(LOG, size=18 * MiB, at=days(1))
    r.note("run.log 长到 18 MiB")
    r.scan(T0, NO_FDA)


# ================================================================ space.system：快照、虚拟磁盘、AI 模型、Xcode

@case("rules/space.system/snapshots-old", "3 个 Time Machine 本地快照，两个留了两天以上：报 2 个、留了 5 天")
def system_snapshots_old(r: Run) -> None:
    r.fx.fake("snapshots", [iso(days(5)), iso(days(3)), iso(T0 - datetime.timedelta(hours=1))])
    r.update()
    r.scan(T0)


@case("rules/space.system/snapshots-recent", "快照都在两天以内（一个正好两天）：正常，不报")
def system_snapshots_recent(r: Run) -> None:
    r.fx.fake("snapshots", [iso(days(2)), iso(T0 - datetime.timedelta(hours=1))])
    r.update()
    r.scan(T0)


@case("rules/space.system/snapshots-unknown", "tmutil 没答（snapshots 是 null）：不报")
def system_snapshots_unknown(r: Run) -> None:
    r.fx.fake("snapshots", None)
    r.update()
    r.scan(T0)


@case("rules/space.system/vm-colima", "colima 的 ~/.colima 3 GiB、~/.lima 2 GiB：合起来 5 GiB，报虚拟磁盘")
def system_vm_colima(r: Run) -> None:
    bulk(r.fx, "~/.colima/_lima/colima", 3 * GiB)
    bulk(r.fx, "~/.lima/default", 2 * GiB)
    r.update()
    r.scan(T0)


@case("rules/space.system/vm-threshold", "OrbStack 正好 5 GiB：报；Podman 差 64 MiB 到 5 GiB：不报")
def system_vm_threshold(r: Run) -> None:
    bulk(r.fx, "~/.orbstack/data", 5 * GiB)
    bulk(r.fx, "~/.local/share/containers/podman/machine/qemu", 5 * GiB - 64 * MiB)
    r.update()
    r.scan(T0)


@case("rules/space.system/vm-docker", "装着 Docker Desktop、容器里的虚拟磁盘 6 GiB：有访问时报；没有完全磁盘访问时记成没看")
def system_vm_docker(r: Run) -> None:
    r.fx.app("~/Applications/Docker.app", "com.docker.docker", "Docker")
    bulk(r.fx, "~/Library/Containers/com.docker.docker/Data/vms/0/data", 6 * GiB)
    r.update()
    r.scan(T0)
    r.note("没有完全磁盘访问")
    r.scan(T0, NO_FDA)


@case("rules/space.system/no-fda-docker-folder", "没装 Docker.app、只有 ~/.docker：有访问时没东西可报；没访问时记成没看")
def system_no_fda_docker_folder(r: Run) -> None:
    r.fx.file("~/.docker/config.json", "{}\n")
    r.update()
    r.scan(T0)
    r.note("没有完全磁盘访问")
    r.scan(T0, NO_FDA)


@case("rules/space.system/no-fda-not-installed", "没有完全磁盘访问、看不出装过 Docker（容器里其实有数据）：不说没看")
def system_no_fda_not_installed(r: Run) -> None:
    bulk(r.fx, "~/Library/Containers/com.docker.docker/Data/vms/0/data", 6 * GiB)
    r.update()
    r.scan(T0, NO_FDA)


@case("rules/space.system/no-fda-orbstack", "OrbStack 的数据只在它的组容器里：有访问时报那里；没访问时记成没看")
def system_no_fda_orbstack(r: Run) -> None:
    r.fx.app("~/Applications/OrbStack.app", "dev.orbstack", "OrbStack")
    r.fx.dir("~/.orbstack/run")
    bulk(r.fx, "~/Library/Group Containers/HUAQ24HBR6.dev.orbstack/data", 6 * GiB)
    r.update()
    r.scan(T0)
    r.note("没有完全磁盘访问")
    r.scan(T0, NO_FDA)


@case("rules/space.system/ai-models", "Hugging Face、LM Studio 的模型 2 GiB 以上的各报一条，所有 AI 工具合起来超过 5 GiB 再报一条总的")
def system_ai_models(r: Run) -> None:
    fx = r.fx
    hub = "~/.cache/huggingface/hub/"
    model(fx, hub + "models--org--big", 2 * GiB, days(30))
    model(fx, hub + "models--org--small", 1 * GiB, days(30))           # 不到 2 GiB：只算进总的
    model(fx, hub + "datasets--x--y", 2 * GiB + 64 * MiB, days(100))
    model(fx, hub + "spaces--a--b", 2 * GiB, days(30))                 # 不是模型也不是数据集：不算
    model(fx, "~/.lmstudio/models/pub/m1", 3 * GiB, days(3))
    model(fx, "~/.cache/lm-studio/models/pub2/m2", 2 * GiB, days(10))  # LM Studio 的另一个地方
    bulk(fx, "~/.ollama/models/blobs", 1 * GiB, at=days(50))           # Ollama 不分个，只算进总的
    r.update()
    r.scan(T0)


@case("rules/space.system/ai-models-total-only", "Ollama 3 GiB、PyTorch 1 GiB、Whisper 1 GiB：没有单个的，合起来正好 5 GiB 报总的")
def system_ai_total_only(r: Run) -> None:
    bulk(r.fx, "~/.ollama/models/blobs", 3 * GiB, at=days(50))
    bulk(r.fx, "~/.cache/torch/hub/checkpoints", 1 * GiB, at=days(50))
    bulk(r.fx, "~/.cache/whisper", 1 * GiB, at=days(50))
    r.update()
    r.scan(T0)


@case("rules/space.system/ai-models-under", "Ollama 3 GiB 加一个差 64 MiB 到 2 GiB 的模型：单个、总的都不够，不报")
def system_ai_under(r: Run) -> None:
    bulk(r.fx, "~/.ollama/models/blobs", 3 * GiB, at=days(50))
    model(r.fx, "~/.cache/huggingface/hub/models--org--m", 2 * GiB - 64 * MiB, days(30))
    r.update()
    r.scan(T0)


@case("rules/space.system/ai-model-cap", "21 个够大的模型：只列最大的 20 个，总的照报")
def system_ai_cap(r: Run) -> None:
    for i in range(21):
        model(r.fx, f"~/.cache/huggingface/hub/models--org--m{i:02d}", 2 * GiB + i * 64 * MiB, days(20 + i))
    r.update()
    r.scan(T0)


DS = "~/Library/Developer/Xcode/"


@case("rules/space.system/xcode-device-support", "设备支持文件：比同一平台最新的旧、一个月没用、100 MiB 以上的才报")
def system_device_support(r: Run) -> None:
    fx = r.fx
    ios = DS + "iOS DeviceSupport/"
    for name, size in [("17.2 (21C62)", 128 * MiB), ("iPhone16,2 17.5 (21F79)", 128 * MiB), ("iPhone16,2 18.1 (22B83)", 128 * MiB),
                       ("16.4.1 (20E252) arm64e", 128 * MiB), ("15.0 (19A346)", 96 * MiB), ("Symbols cache", 128 * MiB)]:
        bulk(fx, ios + name + "/Symbols", size, at=days(90))
    bulk(fx, DS + "watchOS DeviceSupport/10.1 (21S71)/Symbols", 128 * MiB, at=days(90))   # 这个平台只有它
    bulk(fx, DS + "tvOS DeviceSupport/16.0 (20J373)/Symbols", 128 * MiB, at=days(90))
    bulk(fx, DS + "tvOS DeviceSupport/17.0 (21J354)/Symbols", 128 * MiB, at=days(90))
    fx.link(ios + "14.0 (18A373)", fx.p(ios + "17.2 (21C62)"))                         # 链接：不算
    fx.age("~/Library/Developer", days(90))
    fx.file(ios + "16.4.1 (20E252) arm64e/Symbols/recent.bin", size=4096, at=days(3))   # 三天前还在调试这个版本的设备
    r.update()
    r.scan(T0)


@case("rules/space.system/xcode-archives-simulators", "Xcode 的归档 1 GiB、模拟器 5 GiB：只说占了多少")
def system_archives_simulators(r: Run) -> None:
    fx = r.fx
    bulk(fx, DS + "Archives/2025-03-01/App 1.0.xcarchive/Products", 512 * MiB, at=days(400))
    bulk(fx, DS + "Archives/2026-01-10/App 1.1.xcarchive/Products", 512 * MiB, at=days(280))
    fx.file(DS + "Archives/2026-01-10/notes.txt", size=0, at=days(280))   # 不是归档：不算个数
    sim = "~/Library/Developer/CoreSimulator/Devices/"
    bulk(fx, sim + "A1B2C3D4-0000-0000-0000-000000000001/data", 3 * GiB, at=days(10))
    bulk(fx, sim + "A1B2C3D4-0000-0000-0000-000000000002/data", 2 * GiB, at=days(10))
    r.update()
    r.scan(T0)


@case("rules/space.system/xcode-under", "归档差 64 MiB 到 1 GiB、模拟器差 64 MiB 到 5 GiB、旧的设备支持 96 MiB：都不报")
def system_xcode_under(r: Run) -> None:
    fx = r.fx
    bulk(fx, DS + "Archives/2025-03-01/App 1.0.xcarchive/Products", 1 * GiB - 64 * MiB, at=days(400))
    bulk(fx, "~/Library/Developer/CoreSimulator/Devices/A1B2C3D4-0000-0000-0000-000000000001/data", 5 * GiB - 64 * MiB, at=days(10))
    bulk(fx, DS + "iOS DeviceSupport/17.2 (21C62)/Symbols", 96 * MiB, at=days(90))
    bulk(fx, DS + "iOS DeviceSupport/18.1 (22B83)/Symbols", 128 * MiB, at=days(90))
    fx.age("~/Library/Developer", days(90))
    r.update()
    r.scan(T0)


# ================================================================ space.duplicates：一样的大文件（1 MiB 起）

@case("rules/space.duplicates/basic", "文稿和下载里各一份一样的 2 MiB：留文稿里的，下载里的算多占")
def dup_basic(r: Run) -> None:
    r.fx.file("~/Documents/talk.mov", size=2 * MiB, fill=1, at=days(30))
    r.fx.file("~/Downloads/talk (1).mov", size=2 * MiB, fill=1, at=days(2))
    r.update()
    r.scan(T0)


@case("rules/space.duplicates/keep-outside-downloads", "下载里那份更早：照样留下载外面的那份")
def dup_keep_outside(r: Run) -> None:
    r.fx.file("~/Downloads/a.iso", size=2 * MiB, fill=2, at=days(100))
    r.fx.file("~/Movies/a.iso", size=2 * MiB, fill=2, at=days(5))
    r.update()
    r.scan(T0)


@case("rules/space.duplicates/keep-order", "都不在下载里：留最早的；一样早就留路径最短的")
def dup_keep_order(r: Run) -> None:
    fx = r.fx
    fx.file("~/Pictures/x.jpg", size=2 * MiB, fill=3, at=days(10))
    fx.file("~/Documents/x.jpg", size=2 * MiB, fill=3, at=days(20))
    fx.file("~/Music/albums/live/y.wav", size=3 * MiB, fill=4, at=days(50))
    fx.file("~/Music/y.wav", size=3 * MiB, fill=4, at=days(50))
    r.update()
    r.scan(T0)


@case("rules/space.duplicates/three-copies", "三份一样的：留一份，另外两份都算多占")
def dup_three(r: Run) -> None:
    fx = r.fx
    fx.file("~/Documents/report.pdf", size=2 * MiB, fill=5, at=days(60))
    fx.file("~/Desktop/report.pdf", size=2 * MiB, fill=5, at=days(30))
    fx.file("~/Downloads/report (2).pdf", size=2 * MiB, fill=5, at=days(1))
    r.update()
    r.scan(T0)


@case("rules/space.duplicates/clones", "克隆不多占：三份里一份是克隆只算另一份；两份里一份是克隆就不报")
def dup_clones(r: Run) -> None:
    fx = r.fx
    fx.file("~/Documents/talk.mov", size=2 * MiB, fill=6, at=days(30))
    clone(fx, "~/Documents/talk.mov", "~/Movies/talk clone.mov", at=days(10))
    fx.file("~/Downloads/talk (1).mov", size=2 * MiB, fill=6, at=days(2))
    fx.file("~/Documents/cut.mov", size=3 * MiB, fill=7, at=days(30))
    clone(fx, "~/Documents/cut.mov", "~/Movies/cut clone.mov", at=days(10))
    r.update()
    r.scan(T0)


@case("rules/space.duplicates/threshold", "正好 1 MiB 的两份：报；差 1 字节到 1 MiB 的两份：不报")
def dup_threshold(r: Run) -> None:
    fx = r.fx
    fx.file("~/Documents/one.bin", size=1 * MiB, fill=8, at=days(20))
    fx.file("~/Pictures/one.bin", size=1 * MiB, fill=8, at=days(10))
    fx.file("~/Documents/under.bin", size=1 * MiB - 1, fill=9, at=days(20))
    fx.file("~/Pictures/under.bin", size=1 * MiB - 1, fill=9, at=days(10))
    r.update()
    r.scan(T0)


@case("rules/space.duplicates/not-same", "大小一样内容不一样、只有中间不一样、大小不一样、硬链接、符号链接：都不算重复")
def dup_not_same(r: Run) -> None:
    fx = r.fx
    fx.file("~/Documents/a.bin", size=2 * MiB, fill=10, at=days(20))
    fx.file("~/Pictures/a.bin", size=2 * MiB, fill=11, at=days(10))            # 一样大，内容不一样
    middle = bytearray([12]) * (2 * MiB)
    fx.file("~/Documents/b.bin", bytes(middle), at=days(20))
    middle[MiB] ^= 1
    fx.file("~/Pictures/b.bin", bytes(middle), at=days(10))                    # 头尾 64 KiB 一样，中间差一个字节
    fx.file("~/Documents/c.bin", size=2 * MiB, fill=13, at=days(20))
    fx.file("~/Pictures/c.bin", size=2 * MiB + 4 * KiB, fill=13, at=days(10))  # 大小不一样
    fx.file("~/Documents/d.bin", size=2 * MiB, fill=14, at=days(20))
    fx.dir("~/Movies")
    os.link(fx.p("~/Documents/d.bin"), fx.p("~/Movies/d.bin"))                 # 同一个文件的两个名字
    fx.file("~/Documents/e.bin", size=2 * MiB, fill=15, at=days(20))
    fx.link("~/Music/e.bin", fx.p("~/Documents/e.bin"))
    r.update()
    r.scan(T0)


@case("rules/space.duplicates/not-looked", "隐藏的、node_modules 里的、包里的、不在那六个文件夹里的副本：都不看，不报")
def dup_not_looked(r: Run) -> None:
    fx = r.fx
    fx.file("~/Documents/talk.mov", size=2 * MiB, fill=16, at=days(30))
    for rel in ["~/Documents/.talk.mov", "~/Documents/.stash/talk.mov", "~/Documents/site/node_modules/x/talk.mov",
                "~/Pictures/Photos.photoslibrary/originals/talk.mov", "~/Movies/Thing.app/Contents/talk.mov",
                "~/Public/talk.mov", "~/Projects/demo/talk.mov"]:
        fx.file(rel, size=2 * MiB, fill=16, at=days(10))
    r.update()
    r.scan(T0)


@case("rules/space.duplicates/cap", "21 组重复：只报多占最多的 20 组")
def dup_cap(r: Run) -> None:
    for i in range(21):
        size = 1 * MiB + i * 64 * KiB
        r.fx.file(f"~/Documents/dup-{i:02d}.bin", size=size, fill=20 + i, at=days(30))
        r.fx.file(f"~/Pictures/dup-{i:02d}.bin", size=size, fill=20 + i, at=days(10))
    r.update()
    r.scan(T0)


@case("rules/space.duplicates/no-full-disk-access", "没有完全磁盘访问：下载、桌面、文稿不看（记成没看全），影片、音乐里的照报")
def dup_no_fda(r: Run) -> None:
    fx = r.fx
    fx.file("~/Downloads/a.zip", size=2 * MiB, fill=50, at=days(20))
    fx.file("~/Downloads/a (1).zip", size=2 * MiB, fill=50, at=days(10))
    fx.file("~/Movies/b.mov", size=2 * MiB, fill=51, at=days(20))
    fx.file("~/Music/b.mov", size=2 * MiB, fill=51, at=days(10))
    fx.file("~/Documents/c.psd", size=2 * MiB, fill=52, at=days(20))
    fx.file("~/Pictures/c.psd", size=2 * MiB, fill=52, at=days(10))   # 另一份在文稿里：没访问时只看得到一份
    r.update()
    r.scan(T0)
    r.note("没有完全磁盘访问")
    r.scan(T0, NO_FDA)


# ================================================================ cache.rebuildable：工具会自己重建的缓存（50 MiB 起）

KNOWN_CACHES = ["Library/Caches/pip", "Library/Caches/org.swift.swiftpm", "Library/Caches/go-build", "Library/Developer/Xcode/DerivedData",
                ".cargo/registry/cache", ".cargo/registry/src", ".bun/install/cache", ".cache/uv", ".npm/_cacache",
                "Library/Caches/Homebrew", "Library/Caches/Yarn", "Library/Caches/CocoaPods", ".gradle/caches", ".gradle/wrapper/dists",
                "Library/Caches/pypoetry/cache", "Library/Caches/pypoetry/artifacts", "Library/Caches/node-gyp", "Library/Caches/composer",
                "Library/Developer/Xcode/DocumentationCache", "Library/Developer/CoreSimulator/Caches"]


@case("rules/cache.rebuildable/all-known", "认得的 20 个缓存各正好 50 MiB：都报，可以放心删；go、uv、npm 没装，就说删文件夹")
def cache_all_known(r: Run) -> None:
    for rel in KNOWN_CACHES:
        bulk(r.fx, "~/" + rel + "/data", 50 * MiB, at=days(3), chunk=10 * MiB)
    r.update()
    r.scan(T0)


@case("rules/cache.rebuildable/commands-installed", "go、uv、npm 装着：它们的缓存用工具自己的清理命令")
def cache_commands(r: Run) -> None:
    r.fx.fake("installedCommands", ["go", "uv", "npm"])
    for rel in ["Library/Caches/go-build", ".cache/uv", ".npm/_cacache"]:
        bulk(r.fx, "~/" + rel + "/data", 60 * MiB, at=days(3), chunk=10 * MiB)
    r.update()
    r.scan(T0)


@case("rules/cache.rebuildable/just-under", "pip 的缓存差 4 KiB 到 50 MiB：不报")
def cache_just_under(r: Run) -> None:
    bulk(r.fx, "~/Library/Caches/pip/http", 50 * MiB - 4 * KiB, at=days(3), chunk=10 * MiB)
    r.update()
    r.scan(T0)


@case("rules/cache.rebuildable/not-caches", "npx 的包、Yarn 2 的全局缓存、Poetry 的虚拟环境、链接到别处的 Homebrew 缓存：再大也不报")
def cache_not_caches(r: Run) -> None:
    fx = r.fx
    for rel in ["~/.npm/_npx/abc123", "~/.yarn/berry/cache", "~/Library/Caches/pypoetry/virtualenvs/app-py3.12",
                "elsewhere/Homebrew"]:
        bulk(fx, rel, 80 * MiB, at=days(3), chunk=10 * MiB)
    fx.link("~/Library/Caches/Homebrew", fx.p("elsewhere/Homebrew"))
    r.update()
    r.scan(T0)


# ================================================================ leak.temp-prefix：临时目录里一个前缀的一堆没删（20 个、100 MiB 起）

@case("rules/leak.temp-prefix/leak", "25 个 wings-* 各 5 MiB、2 到 5 天没动：报一组，带上头尾日期和每天多少")
def leak_basic(r: Run) -> None:
    temp_group(r.fx, "wings", 25, 5 * MiB, at=lambda i: days(2 + i % 4))
    r.update()
    r.scan(T0)


@case("rules/leak.temp-prefix/too-few", "19 个，每个 6 MiB：不够 20 个，不报")
def leak_too_few(r: Run) -> None:
    temp_group(r.fx, "wings", 19, 6 * MiB, at=days(3))
    r.update()
    r.scan(T0)


@case("rules/leak.temp-prefix/size-threshold", "20 个合起来正好 100 MiB：报；另一组差 4 KiB 到 100 MiB：不报")
def leak_size_threshold(r: Run) -> None:
    temp_group(r.fx, "exact", 20, 5 * MiB, at=days(3))
    temp_group(r.fx, "short", 19, 5 * MiB, at=days(3))
    temp_group(r.fx, "short", 1, 5 * MiB - 4 * KiB, at=days(3), first=19)
    r.update()
    r.scan(T0)


@case("rules/leak.temp-prefix/quiet-day", "一天以内动过的不算：25 个里 6 个 23 小时前动过就不够 20 个；25 小时前动过的照算")
def leak_quiet_day(r: Run) -> None:
    hours = lambda h: T0 - datetime.timedelta(hours=h)   # noqa: E731
    temp_group(r.fx, "busy", 25, 5 * MiB, at=lambda i: hours(23) if i < 6 else days(3))
    temp_group(r.fx, "idle", 25, 5 * MiB, at=lambda i: hours(25) if i < 6 else days(3))
    r.update()
    r.scan(T0)


@case("rules/leak.temp-prefix/files", "直接放在临时目录里的 22 个 upload_* 文件：也算一组")
def leak_files(r: Run) -> None:
    for i in range(22):
        clone(r.fx, _seed(r.fx, 5 * MiB), f"$TMPDIR/upload_Q{i:06d}", at=days(2 + i % 3))
    r.update()
    r.scan(T0)


@case("rules/leak.temp-prefix/not-groups", "系统服务的 com.apple.*、没有随机后缀的、只有后缀没有前缀的：都不算一组")
def leak_not_groups(r: Run) -> None:
    fx = r.fx
    for i in range(25):
        for name in [f"com.apple.Service{i:06d}", f"cache{i}", f"-A{i:05d}", f"log-{i}"]:
            clone(fx, _seed(fx, 5 * MiB), f"$TMPDIR/{name}/x.bin", at=days(3))
            fx.touch(f"$TMPDIR/{name}", days(3))
    r.update()
    r.scan(T0)


@case("rules/leak.temp-prefix/medium", "20 个各 64 MiB，合起来 1.25 GiB：1 GiB 以上算中等")
def leak_medium(r: Run) -> None:
    temp_group(r.fx, "render", 20, 64 * MiB, at=days(3))
    r.update()
    r.scan(T0)


@case("rules/leak.temp-prefix/future-dates", "25 个时间都在将来（解压出来的）：不算最近动过，报；头尾日期写成「?」")
def leak_future(r: Run) -> None:
    temp_group(r.fx, "unpacked", 25, 5 * MiB, at=days(-30))
    r.update()
    r.scan(T0)


@case("rules/leak.temp-prefix/cleaned", "报过以后都删了：下一轮不再报")
def leak_cleaned(r: Run) -> None:
    temp_group(r.fx, "wings", 25, 5 * MiB, at=lambda i: days(2 + i % 4))
    r.update()
    r.scan(T0)
    for i in range(25):
        r.fx.remove(f"$TMPDIR/wings-A{i:05d}")
    r.note("25 个 wings-* 都删了")
    r.scan(days(-1))


@case("rules/leak.temp-prefix/no-tmp", "临时目录不在了：记成没扫描")
def leak_no_tmp(r: Run) -> None:
    r.fx.remove("$TMPDIR")
    r.update()
    r.scan(T0)


# ================================================================ stale.project：半年多没动过的项目（~/Projects 下每个文件夹）

P = "~/Projects/"


def pushed(fx: Fx, name: str, **kw) -> str:
    """一个推过了的老仓库。"""
    return fx.repo(P + name, remote=True, at=OLD, **kw)


@case("rules/stale.project/pushed", "一年多没动、都推过了：删了能从远程找回")
def project_pushed(r: Run) -> None:
    pushed(r.fx, "app")
    r.fx.age(P + "app", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/unpushed", "有一个提交没推：只说，列出会丢什么")
def project_unpushed(r: Run) -> None:
    fx = r.fx
    pushed(fx, "app")
    fx.file(P + "app/more.txt", size=100, at=OLD)
    fx.commit(P + "app", "local only", at=OLD)
    fx.age(P + "app", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/no-remote", "没有远程仓库：只说")
def project_no_remote(r: Run) -> None:
    r.fx.repo(P + "app", remote=False, at=OLD)
    r.fx.age(P + "app", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/dirty", "推过了，但改了一个文件、多了一个没加进去的：两处改动没提交")
def project_dirty(r: Run) -> None:
    fx = r.fx
    pushed(fx, "app")
    fx.file(P + "app/README.md", size=4096, at=OLD)
    fx.file(P + "app/notes.txt", size=100, at=OLD)
    fx.age(P + "app", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/stash", "推过了，但有一个 stash：只说")
def project_stash(r: Run) -> None:
    fx = r.fx
    pushed(fx, "app")
    fx.file(P + "app/README.md", size=4096, at=OLD)
    fx.git(P + "app", "stash", "-q", at=OLD)
    fx.age(P + "app", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/filter", "仓库配了 clean 过滤器：不跑 git status，说没检查改动")
def project_filter(r: Run) -> None:
    fx = r.fx
    pushed(fx, "app")
    fx.git(P + "app", "config", "filter.x.clean", "cat", at=OLD)
    fx.age(P + "app", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/ignored-kept", "被忽略的里头：依赖和日志不算，.env、数据之类只在这里，列前 5 个和一共几项")
def project_ignored(r: Run) -> None:
    fx = r.fx
    keep = [".env", "data/", "local.db", "uploads/", "scratch.txt", "export.csv", "state.json"]
    pushed(fx, "app", ignore=keep + ["node_modules/", "*.log"])
    for rel in [".env", "data/rows.bin", "local.db", "uploads/u.bin", "scratch.txt", "export.csv", "state.json",
                "node_modules/dep/index.js", "debug.log"]:
        fx.file(P + "app/" + rel, size=64, at=OLD)
    fx.age(P + "app", OLD)
    pushed(fx, "web", ignore=["node_modules/", "*.log"])
    fx.file(P + "web/node_modules/dep/index.js", size=64, at=OLD)
    fx.file(P + "web/debug.log", size=64, at=OLD)
    fx.age(P + "web", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/group", "放了几个仓库的文件夹：都推过了就能找回；有没推的、有不在 git 里的就只说")
def project_group(r: Run) -> None:
    fx = r.fx
    pushed(fx, "team/a")
    pushed(fx, "team/b")
    pushed(fx, "group/a")
    pushed(fx, "group/b")
    fx.file(P + "group/b/wip.txt", size=100, at=OLD)
    fx.commit(P + "group/b", "wip", at=OLD)
    fx.file(P + "group/designs/cover.psd", size=1024, at=OLD)
    fx.age(P + "team", OLD)
    fx.age(P + "group", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/empty-repo", "git init 了但没提交过：没有最后提交的日期，没有远程、有没提交的改动")
def project_empty_repo(r: Run) -> None:
    fx = r.fx
    fx.file(P + "app/README.md", size=2048, at=OLD)
    fx.git(P + "app", "init", "-q", "-b", "main", at=OLD)
    fx.age(P + "app", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/git-unreadable", "有 .git 但 git 认不出（空的 .git）：说 git 状态读不出来，只说")
def project_git_unreadable(r: Run) -> None:
    fx = r.fx
    fx.file(P + "broken/README.md", size=2048, at=OLD)
    fx.dir(P + "broken/.git")
    fx.age(P + "broken", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/in-use", "半年内动过一个文件的（181 天前也算）：在用，不报；文件都老、只有提交是新的照报")
def project_in_use(r: Run) -> None:
    fx = r.fx
    pushed(fx, "busy")
    fx.file(P + "busy/src/main.c", size=100, at=OLD)
    fx.commit(P + "busy", "src", at=OLD)
    fx.age(P + "busy", OLD)
    fx.touch(P + "busy/src/main.c", days(100))
    fx.file(P + "notes/a.txt", size=2 * MiB, at=OLD)
    fx.file(P + "notes/b.txt", size=100, at=days(181))
    fx.touch(P + "notes", OLD)
    # 文件都是一年多前的，五天前才提交（git 只动了 .git）：不算动过。
    fx.repo(P + "late", remote=True, at=days(5))
    fx.age(P + "late", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/becomes-stale", "100 天前动过：今天在用；90 天以后（190 天没动）再查就报")
def project_becomes_stale(r: Run) -> None:
    fx = r.fx
    pushed(fx, "app")
    fx.file(P + "app/src/main.c", size=100, at=OLD)
    fx.commit(P + "app", "src", at=OLD)
    fx.age(P + "app", OLD)
    fx.touch(P + "app/src/main.c", days(100))
    r.update()
    r.scan(T0)
    r.note("90 天里没再动")
    r.scan(days(-90))


@case("rules/stale.project/future-dates", "一年多没动、但解压出来的一个文件带着将来的时间：将来的时间不算，照报")
def project_future(r: Run) -> None:
    fx = r.fx
    fx.file(P + "unpacked/notes.txt", size=2 * MiB, at=OLD)
    fx.file(P + "unpacked/vendor/file.bin", size=100, at=days(-400))
    fx.touch(P + "unpacked/vendor", OLD)
    fx.touch(P + "unpacked", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/folders", "不在 git 里的老文件夹：1 MiB 以上的合成一条、按大小排；太小的、直接放在 Projects 里的文件不算")
def project_folders(r: Run) -> None:
    fx = r.fx
    fx.file(P + "notes/a.txt", size=2 * MiB, at=OLD)
    fx.file(P + "big-archive/a.bin", size=5 * MiB, at=OLD)
    fx.file(P + "tiny/a.txt", size=100, at=OLD)
    fx.file(P + "loose.zip", size=3 * MiB, at=OLD)
    for d in ["notes", "big-archive", "tiny"]:
        fx.age(P + d, OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/artifacts", "老项目里能重新生成的（带 package.json 的 node_modules、带 Cargo.toml 的 target）100 MiB 以上：另报一条，只删这些")
def project_artifacts(r: Run) -> None:
    fx = r.fx
    pushed(fx, "web", ignore=["node_modules/"])
    fx.file(P + "web/package.json", "{}\n", at=OLD)
    fx.commit(P + "web", "package.json", at=OLD)
    fx.git(P + "web", "push", "-q", "origin", "main", at=OLD)
    bulk(fx, P + "web/node_modules/dep", 120 * MiB, at=OLD, chunk=10 * MiB)
    fx.age(P + "web", OLD)
    fx.file(P + "rust/Cargo.toml", "[package]\n", at=OLD)
    bulk(fx, P + "rust/target/debug", 110 * MiB, at=OLD, chunk=10 * MiB)
    fx.age(P + "rust", OLD)
    r.update()
    r.scan(T0)


@case("rules/stale.project/artifacts-not", "看着像但不算：没有 package.json、没有 pyvenv.cfg 的、里面有仓库的、git 里有它的文件的、合起来不到 100 MiB 的")
def project_artifacts_not(r: Run) -> None:
    fx = r.fx
    bulk(fx, P + "notes/node_modules/x", 120 * MiB, at=OLD, chunk=10 * MiB)          # 旁边没有 package.json
    fx.file(P + "py/requirements.txt", "x\n", at=OLD)
    bulk(fx, P + "py/venv/lib", 120 * MiB, at=OLD, chunk=10 * MiB)                   # 没有 pyvenv.cfg
    fx.file(P + "vendored/package.json", "{}\n", at=OLD)
    bulk(fx, P + "vendored/node_modules/mine", 120 * MiB, at=OLD, chunk=10 * MiB)
    fx.dir(P + "vendored/node_modules/mine/.git")                                     # 里面有别人的仓库
    fx.repo(P + "gradle", remote=True, at=OLD)
    fx.file(P + "gradle/build.gradle", "\n", at=OLD)
    fx.file(P + "gradle/build/kept.txt", "kept\n", at=OLD)
    fx.commit(P + "gradle", "build", at=OLD)
    fx.git(P + "gradle", "push", "-q", "origin", "main", at=OLD)
    bulk(fx, P + "gradle/build/out", 120 * MiB, at=OLD, chunk=10 * MiB)              # build 里有 git 管着的文件
    fx.file(P + "small/package.json", "{}\n", at=OLD)
    bulk(fx, P + "small/node_modules/dep", 100 * MiB - 4 * KiB, at=OLD, chunk=10 * MiB)   # 差一点到 100 MiB
    for d in ["notes", "py", "vendored", "gradle", "small"]:
        fx.age(P + d, OLD)
    r.update()
    r.scan(T0)


# ================================================================ stale.large-file：一年多没打开的大文件（Spotlight 答的，1 MiB 起）

@case("rules/stale.large-file/opened-long-ago", "上次打开是 800 天前、400 天前：报「2 年多」「一年多」没打开过")
def stale_opened(r: Run) -> None:
    r.fx.file("~/Movies/trip.mov", size=3 * MiB, fill=1, at=days(900))
    r.fx.file("~/Music/set.wav", size=2 * MiB, fill=2, at=days(500))
    spotlit(r, "~/Movies/trip.mov", used=days(800), changed=days(900))
    spotlit(r, "~/Music/set.wav", used=days(400), changed=days(500))
    r.update()
    r.scan(T0)


@case("rules/stale.large-file/never-opened", "没打开过的看放进来的时间：Spotlight 记的、没记就看文件的；十天前放进来的不报")
def stale_never(r: Run) -> None:
    fx = r.fx
    fx.file("~/Downloads/disk.iso", size=2 * MiB, fill=1, at=days(10))
    fx.file("~/Documents/old.zip", size=2 * MiB, fill=2, at=days(1000))
    fx.file("~/Documents/new.zip", size=2 * MiB, fill=3, at=days(10))
    spotlit(r, "~/Downloads/disk.iso", changed=days(400))   # Spotlight 记的是 400 天前（文件上的时间不看）
    spotlit(r, "~/Documents/old.zip")                         # Spotlight 什么都没记：看文件的修改时间
    spotlit(r, "~/Documents/new.zip")
    r.update()
    r.scan(T0)


@case("rules/stale.large-file/cutoff", "正好 365 天前打开过：不报；再早一小时：报；索引落后、其实十天前打开过：不报")
def stale_cutoff(r: Run) -> None:
    fx = r.fx
    for i, name in enumerate(["edge.mov", "past.mov", "recent.mov"]):
        fx.file("~/Movies/" + name, size=2 * MiB, fill=i + 1, at=days(800))
    spotlit(r, "~/Movies/edge.mov", used=days(365))
    spotlit(r, "~/Movies/past.mov", used=days(365) - datetime.timedelta(hours=1))
    spotlit(r, "~/Movies/recent.mov", used=days(10))
    r.update()
    r.scan(T0)


@case("rules/stale.large-file/size", "按占的磁盘算：差 1 字节到 1 MiB 的照报（占满 1 MiB），差 8 KiB 的不报")
def stale_size(r: Run) -> None:
    r.fx.file("~/Movies/almost.mov", size=1 * MiB - 1, fill=1, at=days(800))
    r.fx.file("~/Movies/small.mov", size=1 * MiB - 8 * KiB, fill=2, at=days(800))
    spotlit(r, "~/Movies/almost.mov", used=days(800))
    spotlit(r, "~/Movies/small.mov", used=days(800))
    r.update()
    r.scan(T0)


@case("rules/stale.large-file/skipped-places", "Library、废纸篓、包里的、.git 和 node_modules 里的、不在了的、文件夹、链接：都不报")
def stale_skipped(r: Run) -> None:
    fx = r.fx
    rels = ["~/Library/Caches/big.db", "~/.Trash/old.dmg", "~/Applications/X.app/Contents/big",
            "~/Movies/iMovie Library.imovielibrary/2024/clip.mov", "~/VMs/Win.pvm/disk.hdd",
            "~/Code/repo/.git/objects/pack/x.pack", "~/Code/web/node_modules/x/big.bin", "~/Documents/real.iso"]
    for i, rel in enumerate(rels):
        fx.file(rel, size=2 * MiB, fill=i + 1, at=days(800))
    fx.link("~/Documents/link.iso", fx.p("~/Documents/real.iso"))
    bulk(fx, "~/Documents/folder", 2 * MiB, at=days(800), chunk=1 * MiB)
    for rel in rels[:-1] + ["~/Documents/link.iso", "~/Documents/folder", "~/Documents/gone.iso"]:
        spotlit(r, rel, used=days(800))
    r.update()
    r.scan(T0)


@case("rules/stale.large-file/cap", "21 个很久没打开的：只报最大的 20 个")
def stale_cap(r: Run) -> None:
    for i in range(21):
        rel = f"~/Movies/old-{i:02d}.mov"
        r.fx.file(rel, size=1 * MiB + i * 64 * KiB, fill=i + 1, at=days(900))
        spotlit(r, rel, used=days(800))
    r.update()
    r.scan(T0)


@case("rules/stale.large-file/spotlight-off", "Spotlight 没答（staleFiles 是 null）：记成没扫描")
def stale_spotlight_off(r: Run) -> None:
    r.fx.fake("staleFiles", None)
    r.update()
    r.scan(T0)


@case("rules/stale.large-file/no-full-disk-access", "没有完全磁盘访问：桌面、文稿、下载里的不报（记成没看全），影片里的照报")
def stale_no_fda(r: Run) -> None:
    for i, rel in enumerate(["~/Downloads/disk.iso", "~/Documents/old.zip", "~/Desktop/clip.mov", "~/Movies/trip.mov"]):
        r.fx.file(rel, size=2 * MiB, fill=i + 1, at=days(900))
        spotlit(r, rel, used=days(800))
    r.update()
    r.scan(T0)
    r.note("没有完全磁盘访问")
    r.scan(T0, NO_FDA)



def blob_id(n: int) -> str:
    """一个 64 位十六进制的哈希（共用存储里文件的名字）。"""
    return f"{n:04x}" * 16


def shared_model(fx: Fx, repo: str, blobs: List[int], at: datetime.datetime) -> None:
    """huggingface_hub 2.x 共用存储的样子：文件在 hub/blobs/<前两位>/<哈希>（每个 64 MiB，是同一块的克隆，不另占盘），
    模型文件夹的 blobs/ 里只是指过去的链接，snapshots/ 里的又指向自己的 blobs/。blobs：分片的编号，几个模型用同一个编号
    就是共用的那一份。"""
    hub = "~/.cache/huggingface/hub"
    folder = f"{hub}/models--{repo.replace('/', '--')}"
    for i, n in enumerate(blobs):
        digest = blob_id(n)
        store = f"{hub}/blobs/{digest[:2]}/{digest}"
        if not os.path.exists(fx.p(store)):
            clone(fx, _seed(fx, 64 * MiB), store, at=at)
            fx.file(store + ".refs", repo + "\n", at=at)
        etag = f"{i:04d}{digest[:12]}"
        fx.link(f"{folder}/blobs/{etag}", f"../../blobs/{digest[:2]}/{digest}")
        fx.link(f"{folder}/snapshots/rev1/model-{i:05d}.safetensors", f"../../blobs/{etag}")
    fx.file(f"{folder}/refs/main", "rev1\n", at=at)
    fx.touch(folder, at)


@case("rules/space.system/ai-models-shared-store", "Hugging Face 的共用存储：文件在 hub/blobs，模型文件夹里只有链接；照文件真正占的算，共用的只算一次；删文件夹腾不出空间，说用 hf cache rm、hf cache prune")
def system_ai_shared(r: Run) -> None:
    fx = r.fx
    shared_model(fx, "org/big", list(range(0, 34)), days(30))                        # 34 × 64 MiB ≈ 2.1 GiB
    shared_model(fx, "org/also-big", list(range(14, 34)) + list(range(100, 116)), days(20))   # 前 20 份和上面共用
    shared_model(fx, "org/small", list(range(200, 204)), days(10))
    for n in range(300, 340):                                                       # 没人引用的（删了模型文件夹留下的），2.5 GiB
        clone(fx, _seed(fx, 64 * MiB), f"~/.cache/huggingface/hub/blobs/{blob_id(n)[:2]}/{blob_id(n)}", at=days(40))
    r.update()
    r.scan(T0)


@case("rules/space.system/vm-lume", "lume 的 macOS 虚拟机（~/.lume/<名字>）合起来 6 GiB：报虚拟磁盘，说用 lume 自己删")
def system_vm_lume(r: Run) -> None:
    bulk(r.fx, "~/.lume/macos-dev", 4 * GiB, at=days(30))
    bulk(r.fx, "~/.lume/macos-ci", 2 * GiB, at=days(10))
    r.update()
    r.scan(T0)


# ================================================================ space.ipsw：系统恢复镜像（假目录里 1 MiB 起，真机 1 GiB 起）

@case("rules/space.ipsw/found", "家目录里、它的文件夹和下一层、iTunes 和 lume 放的 .ipsw：各报一条，大的在前；一天内动过的、太小的、链接、更深的、隐藏文件夹里的、Library 别处的不报")
def ipsw_found(r: Run) -> None:
    fx = r.fx
    fx.file("~/lume-ipsw/UniversalMac_26.6.2_25G83_Restore.ipsw", size=3 * MiB, at=days(30))
    fx.file("~/Downloads/iPhone17,1_26.1_23B85_Restore.IPSW", size=2 * MiB, at=days(10))
    fx.file("~/Library/iTunes/iPhone Software Updates/iPhone16,2_18.1_22B83_Restore.ipsw", size=2 * MiB, at=days(200))
    fx.file("~/.lume/UniversalMac_26.5_25F71_Restore.ipsw", size=2 * MiB, at=days(40))
    fx.file("~/old.ipsw", size=1 * MiB, at=days(90))
    # 不报的
    fx.file("~/Downloads/fresh_Restore.ipsw", size=3 * MiB, at=T0 - datetime.timedelta(hours=5))   # 一天内动过：可能还在下、正在用
    fx.file("~/Downloads/tiny.ipsw", size=512 * 1024, at=days(30))                                # 占的盘不到 1 MiB
    fx.link("~/Desktop/linked.ipsw", fx.p("~/lume-ipsw/UniversalMac_26.6.2_25G83_Restore.ipsw"))
    fx.file("~/Projects/vm/images/deep_Restore.ipsw", size=2 * MiB, at=days(30))
    fx.file("~/.cache/hidden_Restore.ipsw", size=2 * MiB, at=days(30))
    fx.file("~/Library/Caches/other_Restore.ipsw", size=2 * MiB, at=days(30))
    fx.file("~/lume-ipsw/notes.txt", size=2 * MiB, at=days(30))
    r.update()
    r.scan(T0)


@case("rules/space.ipsw/no-full-disk-access", "没有完全磁盘访问：下载、桌面、文稿里的恢复镜像不看，记成没看全；别处的照报")
def ipsw_no_fda(r: Run) -> None:
    fx = r.fx
    fx.file("~/lume-ipsw/UniversalMac_26.6.2_25G83_Restore.ipsw", size=3 * MiB, at=days(30))
    fx.file("~/Downloads/iPhone17,1_26.1_23B85_Restore.ipsw", size=2 * MiB, at=days(10))
    r.update()
    r.scan(T0, "--no-full-disk-access")


# ================================================================ space.reconcile：对账；space.system 的 Spotlight 索引

def account(r: Run, used: int, *, total: int = 500 * GiB, free: int = 200 * GiB, available: Optional[int] = None,
            system: Optional[int] = 25 * GiB, swap: Optional[int] = 2 * GiB) -> None:
    """盘上一共用了多少（used），其中系统自己的卷 system、交换文件 swap；free 比 available 多出来的是可清除的。"""
    r.fx.fake("volume", {"free": free, "total": total, "swap": swap, "available": available, "used": used, "system": system})


def data_volume(fx: Fx) -> str:
    """数据卷顶上的样子：应用、系统资源库、共享文件夹各有一点东西，系统的 Spotlight 索引列不出来（只有 root 能看）。
    返回那个列不出来的文件夹，场景跑完要把权限改回去（不然临时目录删不掉）。"""
    fx.file("volume/Applications/Big.app/Contents/MacOS/big", size=3 * MiB)
    fx.file("volume/Library/Application Support/Tool/data.bin", size=2 * MiB)
    fx.file("volume/Users/" + "Shared/shared.bin", size=1 * MiB)
    fx.file("volume/Volumes/Other/elsewhere.bin", size=1 * MiB)   # 别的盘挂在这里：不算
    return fx.dir("volume/.Spotlight-V100", mode=0)


def usage(r: Run, clock: datetime.datetime, *, no_fda: bool = False, note: str = "") -> None:
    r.mcp("resources/read", {"uri": "data/usage"}, clock=clock, no_fda=no_fda, note=note)


@case("rules/space.reconcile/over", "盘上用了 300 GiB，量得到的只有几十 MiB 加系统的 27 GiB：差额过了门槛（30 GiB），报一条，点名量不了的 Spotlight 索引")
def reconcile_over(r: Run) -> None:
    fx = r.fx
    fx.file("~/Movies/film.mov", size=4 * MiB, at=days(30))
    fx.file("~/.Trash/old.bin", size=1 * MiB, at=days(3))
    fx.fake("snapshots", [iso(days(1))])
    locked = data_volume(fx)
    try:
        account(r, 300 * GiB, available=150 * GiB)
        r.update()
        r.scan(T0)
        usage(r, T0, note="data/usage 的 reconcile：各部分、没量的、差额")
    finally:
        os.chmod(locked, 0o755)


@case("rules/space.reconcile/under", "差额 2 GiB 左右，没到门槛：不报，数据里照样给")
def reconcile_under(r: Run) -> None:
    locked = data_volume(r.fx)
    try:
        account(r, 29 * GiB, free=471 * GiB)
        r.update()
        r.scan(T0)
        usage(r, T0)
    finally:
        os.chmod(locked, 0o755)


@case("rules/space.reconcile/no-full-disk-access", "没有完全磁盘访问：文稿和家目录外面都没量，差额再大也不报；数据里说哪些没量、差额是 null")
def reconcile_no_fda(r: Run) -> None:
    r.fx.file("~/Documents/report.pdf", size=2 * MiB, at=days(30))
    locked = data_volume(r.fx)
    try:
        account(r, 300 * GiB)
        r.update()
        r.scan(T0, NO_FDA)
        usage(r, T0, no_fda=True)
    finally:
        os.chmod(locked, 0o755)


@case("rules/space.reconcile/other-user", "别的账户的家目录读不了（可能很大）：不报，数据里记成没量全")
def reconcile_other_user(r: Run) -> None:
    locked = [data_volume(r.fx), r.fx.dir("volume/Users/" + "x/Documents", mode=0)]
    try:
        account(r, 300 * GiB)
        r.update()
        r.scan(T0)
        usage(r, T0)
    finally:
        for d in locked:
            os.chmod(d, 0o755)


@case("rules/space.reconcile/unknown", "不知道盘上一共用了多少（volume 里没有 used）：不对账，数据里是 null")
def reconcile_unknown(r: Run) -> None:
    locked = data_volume(r.fx)
    try:
        disk(r, 200 * GiB, 500 * GiB)
        r.update()
        r.scan(T0)
        usage(r, T0)
    finally:
        os.chmod(locked, 0o755)


SPOTLIGHT = "~/Library/Metadata/CoreSpotlight/index.spotlightV3"


@case("rules/space.system/spotlight-large", "用户的 Spotlight 索引 11 GiB（门槛 10 GiB）：报一条，只说怎么让系统重建")
def system_spotlight_large(r: Run) -> None:
    bulk(r.fx, SPOTLIGHT, 11 * GiB, at=days(2))
    r.update()
    r.scan(T0)


@case("rules/space.system/spotlight-ordinary", "索引 2 GiB：平常的大小，不报")
def system_spotlight_ordinary(r: Run) -> None:
    bulk(r.fx, SPOTLIGHT, 2 * GiB, at=days(2))
    r.update()
    r.scan(T0)
