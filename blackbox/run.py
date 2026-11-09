#!/usr/bin/env python3
"""从外面测 luoke-scan：每个场景造一份假目录，一步一步跑命令行，输出和 blackbox/golden/ 里存的比。

    python3 blackbox/run.py                    跑全部场景，和 golden 比；不一样就列出差别、退出码 1
    python3 blackbox/run.py --record           重录 golden（先确认差别是该有的）
        [--bin <luoke-scan>] [--only <场景前缀>]… [--keep] [-j <并行数>] [--list]

被测的程序：--bin，或环境变量 LUOKE_SCAN_BIN，默认 .build/go/luoke-scan（Go 版）。只用标准库；不碰家目录、不连主控、
不跑 --this-mac。说明见 blackbox/README.md。
"""
from __future__ import annotations

import argparse
import concurrent.futures
import difflib
import importlib
import os
import subprocess
import sys
import traceback
from typing import List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GOLDEN = os.path.join(HERE, "golden")
sys.path.insert(0, HERE)

import harness  # noqa: E402


def load_cases() -> None:
    for name in sorted(os.listdir(os.path.join(HERE, "cases"))):
        if name.endswith(".py") and not name.startswith("_"):
            importlib.import_module("cases." + name[:-3])


def run_one(c: harness.Case, binary: str, keep: bool) -> Tuple[str, Optional[str], Optional[str]]:
    """(场景名, golden 文字, 出错时的说明)。"""
    r = harness.Run(c, binary, keep)
    try:
        c.run(r)
        return c.name, harness.golden(r), None
    except Exception as e:   # 一个场景出错不拖累别的
        detail = "".join(traceback.format_exception_only(type(e), e)).strip()
        if not isinstance(e, harness.Failed):
            detail += "\n" + traceback.format_exc(limit=4)
        if r.steps:
            detail += f"\n  走到第 {len(r.steps)} 步：{r.steps[-1].get('run') or r.steps[-1].get('do')}"
        return c.name, None, detail
    finally:
        if keep:
            print(f"  {c.name} 的假目录留在 {r.work}", file=sys.stderr)
        r.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=os.environ.get("LUOKE_SCAN_BIN") or os.path.join(ROOT, ".build", "go", "luoke-scan"))
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--only", action="append", default=[])
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("-j", type=int, default=min(8, os.cpu_count() or 4))
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()

    load_cases()
    cases = [c for n, c in sorted(harness.CASES.items()) if not a.only or any(n.startswith(o) for o in a.only)]
    if a.list:
        for c in cases:
            print(f"{c.name}  {c.about}")
        return 0
    if not cases:
        print("没有这样的场景", file=sys.stderr)
        return 2
    binary = os.path.abspath(a.bin)
    if not os.access(binary, os.X_OK):
        print(f"找不到被测的程序：{binary}（先 go build -o .build/go/luoke-scan ./cmd/luoke-scan，或用 --bin 指定）", file=sys.stderr)
        return 2

    v = subprocess.run([binary, "version"], stdout=subprocess.PIPE, text=True).stdout.split()
    harness.TOOL_VERSION = v[1] if len(v) > 1 and v[0] == "luoke-scan" else None
    failed: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, a.j)) as pool:
        results = list(pool.map(lambda c: run_one(c, binary, a.keep), cases))
    for name, text, err in results:
        path = os.path.join(GOLDEN, name + ".json")
        if err:
            failed.append(name)
            print(f"✘ {name}：没跑成\n  " + err.replace("\n", "\n  "))
            continue
        assert text is not None
        bad = harness.leaks(text)
        if bad:
            failed.append(name)
            print(f"✘ {name}：输出里有没换掉的路径 {bad}")
            continue
        if a.record:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            old = open(path, encoding="utf-8").read() if os.path.exists(path) else None
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            print(("· " if old == text else "✎ ") + name)
            continue
        if not os.path.exists(path):
            failed.append(name)
            print(f"✘ {name}：还没有 golden（--record 录一份）")
            continue
        want = open(path, encoding="utf-8").read()
        if want == text:
            print(f"✓ {name}")
        else:
            failed.append(name)
            diff = difflib.unified_diff(want.splitlines(), text.splitlines(), "golden/" + name + ".json", "这次", lineterm="", n=2)
            lines = list(diff)
            print(f"✘ {name}：和 golden 不一样\n" + "\n".join(lines[:120]) + ("\n…" if len(lines) > 120 else ""))
    if not a.record:
        recorded = {os.path.relpath(os.path.join(d, f), GOLDEN)[:-5] for d, _, fs in os.walk(GOLDEN) for f in fs if f.endswith(".json")}
        stale = sorted(recorded - set(harness.CASES))
        if stale and not a.only:
            failed += stale
            print("✘ golden 里有、场景里没有的：" + "、".join(stale))
    print(f"\n{len(results) - len([f for f in failed if f in harness.CASES])}/{len(results)} 个场景" + ("录好了" if a.record else "通过"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
