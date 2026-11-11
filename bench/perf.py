#!/usr/bin/env python3
"""螺壳扫描的性能基准：一轮扫描用多久、占多少内存。每个改动性能的 PR 跑一遍，和基线比，变差了就不合。

在一个合成的大号假家目录上跑 release 版的 `luoke-scan scan`（只读；不碰真实的家目录和 ~/.luoke-scan）：
  第 1 轮  新的数据目录，什么都要量（冷）
  第 2 轮  什么都没变（增量：FSEvents 说没改过的都沿用）
  第 3 轮  改了 1% 的文件夹
每轮记墙钟时间、CPU 时间（/usr/bin/time -l，含它起的 clamscan、git），和整轮的内存峰值：每 0.2 秒把扫描和它起的所有
子进程（clamscan、git，按父进程找）的常驻内存加起来，取最大的；扫描进程自己的峰值另记（peak memory footprint）。
给了病毒库（--clamav-db）时再带病毒库跑第 1、2 轮：clamscan 要把整个库载进内存，这是一轮里最吃内存的一步。

    go build -o .build/go/luoke-scan ./cmd/luoke-scan
    python3 bench/perf.py --work <目录> [--files 120000] [--clamav-db /opt/homebrew/var/lib/clamav]
    python3 bench/perf.py ... --baseline bench/perf-baseline.json        # 和基线比：CPU 时间、内存变差超过 25% 退出码 1
    python3 bench/perf.py ... --save-baseline bench/perf-baseline.json   # 把这次的结果存成基线

--work 里的假家目录生成一次（几十秒），参数一样就沿用。病毒库用 APFS 克隆拷进数据目录（cp -c，不多占空间），不联网。
数字只在同一台机器上可比：基线里记着机器型号，型号不同只报数、不比。只用标准库。
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TREE_VERSION = 1
DAY = 86_400
# Worse than the baseline by more than this share, and by more than the floor (noise on small numbers), fails. Wall
# time is reported, not compared: the jobs lower their own priority on purpose (nice 10, disk I/O at the utility tier;
# core.LowerPriority), so how long a round takes depends on what else the Mac is doing; CPU time and memory do not.
TOLERANCE = 0.25
FLOOR = {"cpu_s": 1.0, "peak_mb": 20.0}


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- the fake home

def write(path: str, size: int, rnd: random.Random) -> None:
    with open(path, "wb") as f:
        if size:
            f.write(rnd.randbytes(size))


def spread(root: str, files: int, rnd: random.Random, per_dir: int = 12, depth: int = 3) -> list[str]:
    """`files` files under `root`, about `per_dir` to a folder, `depth` folders deep. Most are empty (a walk costs the
    same per entry whatever its size); one in seven has a few KB so sizes add up to something. Returns the folders."""
    dirs = []
    made = 0
    i = 0
    while made < files:
        parts = [f"d{(i // (8 ** k)) % 8}" for k in range(depth - 1, -1, -1)]
        d = os.path.join(root, *parts, f"n{i}")
        os.makedirs(d, exist_ok=True)
        dirs.append(d)
        for j in range(min(per_dir, files - made)):
            write(os.path.join(d, f"f{j}.bin"), rnd.randint(1, 16) * 1024 if rnd.random() < 0.15 else 0, rnd)
            made += 1
        i += 1
    return dirs


def age(root: str, seconds: float) -> None:
    """Dates everything under `root` (and it) `seconds` back: old projects, unused app data."""
    t = time.time() - seconds
    for dirpath, dirnames, filenames in os.walk(root):
        for n in filenames + dirnames:
            os.utime(os.path.join(dirpath, n), (t, t), follow_symlinks=False)
    os.utime(root, (t, t))


def build_tree(work: str, files: int) -> dict:
    """The fake home, temp dir and project folder. Shares follow what real homes spend their entries on: tool caches,
    node_modules in old projects, app data, documents, many leftover temp folders, a month of downloads."""
    marker = os.path.join(work, "tree.json")
    want = {"version": TREE_VERSION, "files": files}
    if os.path.exists(marker):
        with open(marker, encoding="utf-8") as f:
            have = json.load(f)
        if {k: have.get(k) for k in want} == want:
            log(f"假家目录沿用上次的：{work}")
            return have
        log("参数变了，重新生成假家目录")
    for name in ("home", "tmp"):
        shutil.rmtree(os.path.join(work, name), ignore_errors=True)
    rnd = random.Random(20261026)
    home, tmp = os.path.join(work, "home"), os.path.join(work, "tmp")
    started = time.time()
    log(f"生成假家目录：{files} 个文件……")
    lib = os.path.join(home, "Library")
    spread(os.path.join(lib, "Caches", "pip", "http-v2"), files * 25 // 100, rnd)
    for n in range(30):
        app = os.path.join(lib, "Application Support", f"io.example.app{n}")
        spread(app, files * 15 // 100 // 30, rnd, depth=2)
        if n % 3 == 0:
            age(app, 200 * DAY)            # left behind by an app that is gone
    projects = os.path.join(home, "Projects")
    for n in range(40):
        p = os.path.join(projects, f"proj{n}")
        spread(os.path.join(p, "node_modules"), files * 35 // 100 // 40, rnd, depth=2)
        write(os.path.join(p, "README.md"), 512, rnd)
        if n % 4 == 0:
            subprocess.run(["git", "init", "-q", p], check=True)
        if n % 2 == 0:
            age(p, 400 * DAY)              # untouched for over a year
    spread(os.path.join(home, "Documents"), files * 10 // 100, rnd)
    spread(os.path.join(home, "Movies", "Library"), files * 9 // 100, rnd)
    for n in range(40):                    # a tool that leaks a temp folder per run
        spread(os.path.join(tmp, f"wings-{rnd.getrandbits(40):010x}"), files * 5 // 100 // 40, rnd, depth=1)
    downloads = os.path.join(home, "Downloads")
    os.makedirs(downloads, exist_ok=True)
    for n in range(files // 100 // 5):     # what the virus scan looks at: last month's downloads
        write(os.path.join(downloads, f"download-{n}.bin"), rnd.randint(1, 64) * 1024, rnd)
    have = dict(want, seconds=round(time.time() - started, 1))
    with open(marker, "w", encoding="utf-8") as f:
        json.dump(have, f)
    log(f"生成好了（{have['seconds']} 秒）")
    return have


def touch_one_percent(work: str) -> list[tuple[str, str, float]]:
    """Adds a file to 1% of the folders: what a day of normal use changes, roughly. Returns what `untouch` needs to
    put the tree back as it was (the same tree every run, or runs would not compare)."""
    home = os.path.join(work, "home")
    dirs = sorted(d for d, _, _ in os.walk(home))
    rnd = random.Random(len(dirs))
    done = []
    for d in rnd.sample(dirs, max(1, len(dirs) // 100)):
        before = os.stat(d).st_mtime
        f = os.path.join(d, "touched.bin")
        with open(f, "wb") as h:
            h.write(b"x" * 4096)
        done.append((d, f, before))
    return done


def untouch(done: list[tuple[str, str, float]]) -> None:
    for d, f, before in done:
        os.remove(f)
        os.utime(d, (before, before))


# ---------------------------------------------------------------- measuring

TIME_FIELDS = {"maximum resident set size": "max_rss", "peak memory footprint": "peak_footprint"}


def tree_rss(root: int) -> int:
    """Resident memory of `root` and all its descendants, in bytes. By parent, not process group: Foundation's Process
    can start a tool in a group of its own."""
    r = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,rss="], capture_output=True, text=True)
    kids: dict[int, list[int]] = {}
    rss: dict[int, int] = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3:
            pid, ppid = int(parts[0]), int(parts[1])
            kids.setdefault(ppid, []).append(pid)
            rss[pid] = int(parts[2]) * 1024
    total, todo = 0, [root]
    while todo:
        pid = todo.pop()
        total += rss.get(pid, 0)
        todo += kids.get(pid, [])
    return total


def measure(cmd: list[str]) -> dict:
    """Runs `cmd` under /usr/bin/time -l: wall and CPU seconds (with the tools it starts), the tool's own peak footprint,
    and the peak of it and everything it started, sampled every 0.2 s."""
    p = subprocess.Popen(["/usr/bin/time", "-l"] + cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    peak_group = 0
    while p.poll() is None:
        peak_group = max(peak_group, tree_rss(p.pid))
        time.sleep(0.2)
    err = p.stderr.read()
    if p.returncode != 0:
        raise SystemExit(f"{' '.join(cmd[:2])} 退出码 {p.returncode}：{err.strip()[-800:]}")
    out = {}
    for line in err.splitlines():
        m = re.match(r"\s*([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys", line)
        if m:
            out["wall_s"] = float(m.group(1))
            out["cpu_s"] = round(float(m.group(2)) + float(m.group(3)), 2)
        m = re.match(r"\s*(\d+)\s+(.+?)\s*$", line)
        if m and m.group(2) in TIME_FIELDS:
            out[TIME_FIELDS[m.group(2)]] = int(m.group(1))
    own = out.get("peak_footprint") or out.get("max_rss") or 0
    return {"wall_s": out.get("wall_s", 0.0), "cpu_s": out.get("cpu_s", 0.0), "peak_mb": round(peak_group / 2**20, 1),
            "own_peak_mb": round(own / 2**20, 1)}


def clone_db(src: str, data: str) -> None:
    dst = os.path.join(data, "clamav")
    os.makedirs(dst, exist_ok=True)
    for n in os.listdir(src):
        if n.endswith((".cvd", ".cld", ".cud")):
            subprocess.run(["cp", "-c", "-p", os.path.join(src, n), os.path.join(dst, n)], check=True)


def rounds(binary: str, work: str, label: str, db: str | None, count: int) -> dict:
    data = os.path.join(work, f"data-{label}")
    shutil.rmtree(data, ignore_errors=True)
    os.makedirs(data)
    if db:
        clone_db(db, data)
    home = os.path.join(work, "home")
    cmd = [binary, "scan", "--home", home, "--data", data, "--tmp", os.path.join(work, "tmp"),
           "--projects", os.path.join(home, "Projects"), "--json"]
    out = {}
    names = ["cold", "unchanged", "one_percent"][:count]
    for name in names:
        touched = []
        if name == "one_percent":
            touched = touch_one_percent(work)
            time.sleep(3)                  # FSEvents writes its journal a moment later
            log(f"  改了 {len(touched)} 个文件夹")
        m = measure(cmd)
        untouch(touched)
        with open(os.path.join(data, "last-report.json"), encoding="utf-8") as f:
            report = json.load(f)
        m["findings"] = len(report.get("findings", []))
        m["slowest"] = sorted(report.get("ruleSeconds", {}).items(), key=lambda kv: -kv[1])[:3]
        out[name] = m
        log(f"  {label}/{name}: {m['wall_s']} 秒（CPU {m['cpu_s']} 秒），内存峰值 {m['peak_mb']} MB（扫描自己 {m['own_peak_mb']} MB），"
            f"{m['findings']} 条；最慢 {', '.join(f'{k} {v}s' for k, v in m['slowest'])}")
    return out


def machine() -> dict:
    def sysctl(k):
        return subprocess.run(["sysctl", "-n", k], capture_output=True, text=True).stdout.strip()
    return {"model": sysctl("hw.model"), "memory_gb": int(sysctl("hw.memsize") or 0) // 2**30, "macos": platform.mac_ver()[0]}


def compare(now: dict, base: dict) -> list[str]:
    worse = []
    for mode, rs in now["runs"].items():
        for name, m in rs.items():
            b = base.get("runs", {}).get(mode, {}).get(name)
            if not b:
                continue
            for k, floor in FLOOR.items():
                if m[k] > b[k] * (1 + TOLERANCE) and m[k] - b[k] > floor:
                    worse.append(f"{mode}/{name} {k}: {b[k]} → {m[k]}")
    return worse


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", required=True, help="放假家目录的目录（第一次给空目录）")
    ap.add_argument("--bin", default=os.path.join(ROOT, ".build", "go", "luoke-scan"))
    ap.add_argument("--files", type=int, default=120_000)
    ap.add_argument("--clamav-db", help="病毒库目录（比如 /opt/homebrew/var/lib/clamav）；给了就带病毒库再跑两轮")
    ap.add_argument("--baseline")
    ap.add_argument("--save-baseline")
    ap.add_argument("--label", default="", help="写进结果里，说明这是哪个改动")
    a = ap.parse_args()
    if not os.access(a.bin, os.X_OK):
        log(f"没有 {a.bin}：先 go build -o .build/go/luoke-scan ./cmd/luoke-scan")
        return 2
    os.makedirs(a.work, exist_ok=True)
    work = os.path.realpath(a.work)
    tree = build_tree(work, a.files)
    commit = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    result = {"label": a.label, "commit": commit, "machine": machine(), "files": tree["files"], "runs": {}}
    log("不带病毒库：")
    result["runs"]["no_db"] = rounds(a.bin, work, "no_db", None, 3)
    if a.clamav_db:
        log("带病毒库：")
        result["runs"]["with_db"] = rounds(a.bin, work, "with_db", a.clamav_db, 2)
    print(json.dumps(result, ensure_ascii=False, indent=1))
    if a.save_baseline:
        with open(a.save_baseline, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=1)
            f.write("\n")
        log(f"存成基线：{a.save_baseline}")
    if a.baseline:
        with open(a.baseline, encoding="utf-8") as f:
            base = json.load(f)
        if base.get("machine", {}).get("model") != result["machine"]["model"] or base.get("files") != result["files"]:
            log(f"基线是 {base.get('machine', {}).get('model')}、{base.get('files')} 个文件，这次不同：只报数、不比")
            return 0
        worse = compare(result, base)
        if worse:
            log("比基线变差了：\n  " + "\n  ".join(worse))
            return 1
        log("没有比基线变差")
    return 0


if __name__ == "__main__":
    sys.exit(main())
