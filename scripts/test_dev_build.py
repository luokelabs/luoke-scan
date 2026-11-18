#!/usr/bin/env python3
"""螺壳开发实例用的扫描：scripts/package_app.py --fixture-only 什么时候打、怎么标，scripts/make_fixture.py 造在哪、
造出来的假 Mac 能不能查。

    python3 -I scripts/test_dev_build.py      # 有 .build/go/luoke-scan（或 LUOKE_SCAN_BIN）时连造假 Mac 一起测

只用标准库；不编译、不打包（打包的两种产物由 package_app.py 自己核对），只在临时目录里读写。
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import make_fixture  # noqa: E402
import package_app  # noqa: E402

BIN = os.environ.get("LUOKE_SCAN_BIN") or os.path.join(ROOT, ".build", "go", "luoke-scan")
CORE = "github.com/luokelabs/luoke-scan/internal/core"


def args(**kw) -> argparse.Namespace:
    base = {"fixture_only": True, "verify": None, "verify_app": None, "tarball": False}
    base.update(kw)
    return argparse.Namespace(**base)


def script(name: str, *argv: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", os.path.join(HERE, name), *argv], capture_output=True, text=True,
                          env=env, timeout=600)


class PackageApp(unittest.TestCase):
    def test_flags(self):
        self.assertEqual(package_app.go_flags(False, ""), f"-X {CORE}.packedFlag=1")
        self.assertEqual(package_app.go_flags(False, "ABCDE12345"), f"-X {CORE}.packedFlag=1 -X {CORE}.ReleaseTeam=ABCDE12345")
        self.assertEqual(package_app.go_flags(True, ""), "-X main.fixtureOnlyFlag=1")
        with self.assertRaises(SystemExit):
            package_app.go_flags(True, "ABCDE12345")

    def test_linked_version(self):
        self.assertEqual(package_app.linked_version("luoke-scan", "0.3.35", True), "0.3.35+fixture")
        self.assertEqual(package_app.linked_version("luoke-scan-admin", "0.3.35", True), "0.3.35")
        self.assertEqual(package_app.linked_version("luoke-scan", "0.3.35", False), "0.3.35")

    def test_only_for_a_development_instance(self):
        ok = {"LUOKE_BUNDLE_ID": "ai.luoke.core.agent.lab"}
        self.assertEqual(package_app.fixture_only_problem(args(), ok), "")
        self.assertEqual(package_app.fixture_only_problem(args(fixture_only=False), {}), "")
        self.assertEqual(package_app.fixture_only_problem(args(verify="/x"), {}), "")   # checking a folder builds nothing
        for bundle in ("", "ai.luoke.core", "ai.luoke.core.lab", "ai.luoke.core.dev", "ai.luoke.core.Agent.lab",
                       "ai.luoke.core.agent.lab.x", "ai.luoke.scan"):
            self.assertNotEqual(package_app.fixture_only_problem(args(), {"LUOKE_BUNDLE_ID": bundle}), "", bundle)
        self.assertNotEqual(package_app.fixture_only_problem(args(), {**ok, "LUOKE_RELEASE_TEAM": "ABCDE12345"}), "")
        self.assertNotEqual(package_app.fixture_only_problem(args(tarball=True), ok), "")
        self.assertNotEqual(package_app.fixture_only_problem(args(verify_app="/x.app"), ok), "")

    def test_environment_switch_is_refused_before_anything_runs(self):
        env = {"PATH": "/usr/bin:/bin", "LUOKE_SCAN_FIXTURE_ONLY": "1"}
        r = script("package_app.py", "--verify-app", "/nonexistent/螺壳.app", env=env)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("--verify-app", r.stderr)
        r = script("package_app.py", "--out", "/nonexistent", env={**env, "LUOKE_BUNDLE_ID": "ai.luoke.core"})
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("ai.luoke.core.<名字>.lab", r.stderr)

    def test_word_matches_the_program(self):
        with open(os.path.join(ROOT, "cmd", "luoke-scan", "fixtureonly.go"), encoding="utf-8") as f:
            self.assertIn(f'const fixtureOnlyWord = "{package_app.FIXTURE_ONLY_WORD}"', f.read())
        self.assertEqual(make_fixture.FIXTURE_ONLY_WORD, package_app.FIXTURE_ONLY_WORD)


class Target(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="luoke-scan-test-target-")
        self.addCleanup(make_fixture.remove, self.tmp)

    def test_where_it_builds(self):
        p = make_fixture.target_problem
        self.assertEqual(p(os.path.join(self.tmp, "new")), "")
        os.makedirs(os.path.join(self.tmp, "empty"))
        self.assertEqual(p(os.path.join(self.tmp, "empty")), "")
        os.makedirs(os.path.join(self.tmp, "made"))
        open(os.path.join(self.tmp, "made", make_fixture.MARK), "w").close()
        open(os.path.join(self.tmp, "made", "x"), "w").close()
        self.assertEqual(p(os.path.join(self.tmp, "made")), "")
        os.makedirs(os.path.join(self.tmp, "other"))
        open(os.path.join(self.tmp, "other", "x"), "w").close()
        self.assertNotEqual(p(os.path.join(self.tmp, "other")), "")
        os.symlink(os.path.join(self.tmp, "empty"), os.path.join(self.tmp, "link"))
        self.assertNotEqual(p(os.path.join(self.tmp, "link")), "")
        open(os.path.join(self.tmp, "file"), "w").close()
        self.assertNotEqual(p(os.path.join(self.tmp, "file")), "")
        for home in make_fixture.homes():
            self.assertNotEqual(p(home), "")
            self.assertNotEqual(p(os.path.dirname(home)), "")
        self.assertNotEqual(p("/"), "")

    def test_remove_unlocks(self):
        root = os.path.join(self.tmp, "fake")
        os.makedirs(os.path.join(root, "ro"))
        locked = os.path.join(root, "locked")
        open(locked, "w").close()
        os.chflags(locked, stat.UF_IMMUTABLE)
        os.chmod(os.path.join(root, "ro"), 0o555)
        make_fixture.remove(root)
        self.assertFalse(os.path.lexists(root))


@unittest.skipUnless(os.access(BIN, os.X_OK), f"没有 {BIN}：先 go build -o .build/go/luoke-scan ./cmd/luoke-scan")
class MakeFixture(unittest.TestCase):
    """A scene made in a folder of the test's own: its arguments, its data beside it, a request answered from it."""

    def test_make_serve_remake_remove(self):
        tmp = tempfile.mkdtemp(prefix="luoke-scan-test-make-")
        self.addCleanup(make_fixture.remove, tmp)
        folder = os.path.join(tmp, "scan-fixture")
        env = {k: v for k, v in os.environ.items() if not k.startswith("LUOKE_")}
        r = script("make_fixture.py", "first-run-no-fda", folder, "--bin", BIN, "--json", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        got = json.loads(r.stdout)
        root = os.path.realpath(folder)
        self.assertEqual(got, ["--fixture", root, "--clock", "2026-10-20T12:00:00Z", "--no-full-disk-access"])
        with open(os.path.join(root, make_fixture.MARK), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["args"], got)
        status = subprocess.run([BIN, "status", "--data", os.path.join(root, "data"), "--json"], capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(status.returncode, 0, status.stderr)   # the scene's round is there before anyone asks
        req = {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": "summary"}}
        served = subprocess.run([BIN, "mcp", *got], input=json.dumps(req), capture_output=True, text=True, timeout=120,
                                env={**env, "HOME": tmp, "TZ": "Asia/Shanghai"})
        self.assertEqual(served.returncode, 0, served.stderr)
        self.assertIn("result", json.loads(served.stdout))
        r = script("make_fixture.py", "malware", folder, "--bin", BIN, env=env)   # made before: replaced
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("--no-full-disk-access", r.stdout)
        r = script("make_fixture.py", "--remove", folder, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.lexists(root))


if __name__ == "__main__":
    unittest.main()
