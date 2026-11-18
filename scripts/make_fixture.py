#!/usr/bin/env python3
"""把 fixtures/agent 里一个场景的假 Mac 造在给定的目录里，给螺壳开发实例里那份只查假 Mac 的扫描用
（scripts/package_app.py --fixture-only）。

    python3 scripts/make_fixture.py <场景> <目录> [--bin <开发版 luoke-scan>] [--json]
    python3 scripts/make_fixture.py --list              # 有哪些场景
    python3 scripts/make_fixture.py --remove <目录>     # 删掉本脚本造的假 Mac

照 scripts/record_agent_fixtures.py 里同名场景的造法：假用户目录、假的病毒库和扫描器、假的进程和系统设置（fakes.json），
跑到 agent 第一次调工具之前：之前的几轮都查过了，什么都还没点（fda-granted、full-report、crowded 没有点按，跑完为止）。
标准输出一行：给 luoke-scan 的参数 `--fixture <目录> --clock <时间> [--no-full-disk-access]`（--json 时是 JSON 数组），
mcp 和 scan（`--autoclean`、`--quick`）都接在这几个后面。报告、清理记录、设置在 <目录>/data，移到废纸篓的在 <目录>/Trash，
不用另给 --data。时钟停在场景的时间（--clock），每次起都一样。

造的时候用开发版的 luoke-scan（--bin；没给就编一份放在临时目录，用完删掉；只查假 Mac 的那份造不了），它看到的 HOME 是
临时目录里一个空目录；不碰家目录，不连主控，不联网。<目录> 要么还没有、要么是空的、要么是本脚本造过的（里面有
make_fixture.json）：造过的先整个删掉再造；别的目录不动，家目录和它上面的目录不用。feedback-152 里有锁定的文件和只读的
文件夹，`rm -rf` 删不掉，用 --remove。只用标准库。
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)   # python3 -I leaves the script's own folder off sys.path

import record_agent_fixtures as rec  # noqa: E402
from fx import iso  # noqa: E402  (record_agent_fixtures put blackbox/ on sys.path)
from harness import Failed  # noqa: E402

MARK = "make_fixture.json"   # in a fake Mac this script made: only such a folder is replaced or removed
FIXTURE_ONLY_WORD = "只查假 Mac 的开发构建"   # cmd/luoke-scan/fixtureonly.go: the fixture-only copy says so in its version line


class Ready(Exception):
    """The scene's fake Mac is as the agent first finds it: the next step would be the first tool call."""


class Maker(rec.Recorder):
    """A scene's recorder that stops before the first tool call (a click, a tool the model calls): the rounds before it
    have run and the reads before it have been answered; nothing has been clicked."""

    def request(self, file, what, method, params=None, user_action=None):
        if method == "tools/call":
            raise Ready()
        return super().request(file, what, method, params, user_action)


def scan_args(root: str, r: rec.Recorder) -> List[str]:
    """What luoke-scan is given to look at the fake Mac as the scene left it."""
    assert r.clock is not None
    return ["--fixture", root, "--clock", iso(r.clock)] + (["--no-full-disk-access"] if r.no_fda else [])


def homes() -> List[str]:
    out = {os.path.realpath(os.path.expanduser("~"))}
    try:
        out.add(os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir))
    except KeyError:
        pass
    return sorted(out)


def target_problem(path: str) -> str:
    """Why this script may not build a fake Mac in path (or remove it), "" when it may: a folder not there yet, an empty
    one, or one it made before (MARK in it); never a link, a home folder or a folder above one."""
    given = os.path.abspath(path)
    if os.path.islink(given):
        return f"{given} 是链接：给真正的目录"
    root = os.path.realpath(given)
    for home in homes():
        if root == home or home.startswith(root.rstrip(os.sep) + os.sep):
            return f"{root} 是家目录或在它上面：假 Mac 造在别处（例如开发实例自己的目录里）"
    if not os.path.lexists(root):
        return ""
    if not os.path.isdir(root):
        return f"{root} 不是文件夹"
    if not os.listdir(root) or os.path.isfile(os.path.join(root, MARK)):
        return ""
    return f"{root} 里已经有别的东西，不是本脚本造的假 Mac（没有 {MARK}）：换一个目录，或者自己先清空"


def remove(root: str) -> None:
    """A fake Mac this script made, gone: locked files and read-only folders (feedback-152) made removable first."""
    if os.path.lexists(root):
        rec.unlock(root)
        shutil.rmtree(root)


def go() -> str:
    return os.environ.get("GO") or shutil.which("go") or next(
        (g for g in ("/usr/local/go/bin/go", "/opt/homebrew/bin/go") if os.access(g, os.X_OK)), "go")


def dev_binary(given: Optional[str], tmp: str) -> str:
    """The development luoke-scan that makes the fake Mac: --bin, or one built from this checkout into tmp."""
    if given:
        binary = os.path.abspath(given)
    else:
        binary = os.path.join(tmp, "luoke-scan")
        env = {**os.environ, "CGO_ENABLED": "1",
               "CC": os.environ.get("CC") or ("/usr/bin/clang" if os.path.exists("/usr/bin/clang") else "clang")}
        r = subprocess.run([go(), "build", "-trimpath", "-o", binary, "./cmd/luoke-scan"], cwd=ROOT, env=env,
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(f"编 luoke-scan 没成：{(r.stderr or r.stdout).strip()[-1500:]}")
    r = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise SystemExit(f"{binary} 跑不起来（version 退出码 {r.returncode}）")
    if FIXTURE_ONLY_WORD in r.stdout:
        raise SystemExit(f"{binary} 是{FIXTURE_ONLY_WORD}：造假 Mac 要开发版（go build -o .build/go/luoke-scan ./cmd/luoke-scan）")
    return binary


def make(scene: rec.Scenario, root: str, binary: str) -> List[str]:
    """Builds scene's fake Mac in root (empty or not there) and returns the arguments for luoke-scan."""
    os.makedirs(root, exist_ok=True)
    mark = os.path.join(root, MARK)
    with open(mark, "w", encoding="utf-8") as f:   # first: a half-made one is still this script's to replace
        json.dump({"scene": scene.id, "ready": False}, f)
    r = Maker(scene.id, binary, keep=False, fixture=root)
    try:
        try:
            scene.run(r)
        except Ready:
            pass
        args = scan_args(root, r)
    finally:
        shutil.rmtree(r.work, ignore_errors=True)   # only the empty HOME the program saw and its working folder
    with open(mark, "w", encoding="utf-8") as f:
        json.dump({"scene": scene.id, "title": scene.title, "ready": True, "args": args}, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return args


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scene", nargs="?", help="场景（--list 列出）")
    ap.add_argument("folder", nargs="?", help="造在哪个目录（luoke-scan 的 --fixture）")
    ap.add_argument("--bin", help="造的时候用的开发版 luoke-scan（没给就编一份）")
    ap.add_argument("--json", action="store_true", help="参数打印成 JSON 数组")
    ap.add_argument("--list", action="store_true", help="列出场景")
    ap.add_argument("--remove", metavar="FOLDER", help="删掉本脚本造的假 Mac")
    a = ap.parse_args()
    scenes = {s.id: s for s in rec.SCENARIOS}
    if a.list:
        for s in rec.SCENARIOS:
            print(f"{s.id}\t{s.title}")
        return 0
    if a.remove:
        why = target_problem(a.remove)
        if why:
            print(why, file=sys.stderr)
            return 2
        remove(os.path.realpath(os.path.abspath(a.remove)))
        return 0
    if not a.scene or not a.folder:
        ap.print_usage(sys.stderr)
        return 2
    if a.scene not in scenes:
        print(f"没有场景 {a.scene}：有 {', '.join(scenes)}", file=sys.stderr)
        return 2
    why = target_problem(a.folder)
    if why:
        print(why, file=sys.stderr)
        return 2
    root = os.path.realpath(os.path.abspath(a.folder))
    with tempfile.TemporaryDirectory(prefix="luoke-scan-make-fixture-") as tmp:
        binary = dev_binary(a.bin, tmp)
        remove(root)
        try:
            args = make(scenes[a.scene], root, binary)
        except Failed as e:
            remove(root)
            print(f"没造成：{e}", file=sys.stderr)
            return 2
    print(f"{a.scene}（{scenes[a.scene].title}）的假 Mac 造好了：{root}；数据在 {os.path.join(root, 'data')}", file=sys.stderr)
    print(json.dumps(args, ensure_ascii=False) if a.json else shlex.join(args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
