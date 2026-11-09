"""已知的恶意包（supplychain.malicious）：项目的锁文件、全局装的包，和本机导入的 OSV 恶意包名单（MAL- 开头的）比对。

名单只从本机的文件导入（`malicious-import`），不联网；没导入过名单时什么也不说。包名、MAL 编号都是编出来的
（evil-、fixture- 开头），OSV 记录只写规则用到的几个键。每个场景旁边放几个「差一点」的：版本不在名单上的、
node_modules 里面的锁文件、太深的、测试数据和示例里的、git 和本地的依赖（名字一样也不算）、npm link 的链接。
"""
from __future__ import annotations

import datetime
import json
import os
import zipfile
from typing import Any, Dict, List, Optional

from agent import OUTBOX, Agent
from fx import T0, Fx
from harness import Run, case

LIST_DAY = "2026-10-15T08:00:00Z"


def osv(id_: str, eco: str, name: str, versions: Optional[List[str]] = None, *, all_versions: bool = False,
        ranges: Optional[List[Dict[str, str]]] = None, modified: str = LIST_DAY) -> Dict[str, Any]:
    aff: Dict[str, Any] = {"package": {"ecosystem": eco, "name": name}}
    if versions:
        aff["versions"] = versions
    if all_versions:
        aff["ranges"] = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
    if ranges:
        aff["ranges"] = [{"type": "ECOSYSTEM", "events": ranges}]
    return {"schema_version": "1.5.0", "id": id_, "modified": modified, "published": modified,
            "summary": f"Malicious code in {name} ({eco})", "affected": [aff]}


def osv_tree(fx: Fx, records: List[Dict[str, Any]], where: str = "osv") -> str:
    """OpenSSF 那样的一棵树：osv/malicious/<生态>/<包名>/<编号>.json（放在假目录的根下，不在家目录里）。"""
    for rec in records:
        a = rec["affected"][0]["package"]
        fx.json(f"{where}/malicious/{a['ecosystem'].lower()}/{a['name']}/{rec['id']}.json", rec)
    return fx.p(where)


def standard_list(fx: Fx) -> str:
    return osv_tree(fx, [
        osv("MAL-2026-9001", "npm", "evil-stealer", all_versions=True),
        osv("MAL-2026-9002", "npm", "@fixture/evil-utils", ["1.0.1", "1.0.2"]),
        osv("MAL-2026-9003", "npm", "fixture-colors", ["1.4.1"]),
        osv("MAL-2026-9004", "PyPI", "Evil_Requests", ["2.31.1"]),
        osv("MAL-2026-9005", "PyPI", "fixture-setup-tools", all_versions=True),
        osv("MAL-2026-9006", "crates.io", "evil_crate", ranges=[{"introduced": "0.3.0"}, {"fixed": "0.3.5"}]),
        osv("GHSA-fixture-0001", "npm", "lodash", ["4.17.20"]),     # 不是 MAL-：不留
    ])


def import_list(r: Run, path: str) -> None:
    r.cli("malicious-import", "--data", r.fx.data, path)


def npm_lock(packages: Dict[str, str], *, name: str = "app") -> Dict[str, Any]:
    pk: Dict[str, Any] = {"": {"name": name, "version": "1.0.0"}}
    for key, version in packages.items():
        pkg = key.rsplit("node_modules/", 1)[-1]
        tarball = f"https://registry.npmjs.org/{pkg}/-/{pkg.split('/')[-1]}-{version}.tgz"
        pk[key] = {"version": version, "resolved": tarball, "integrity": "sha512-FIXTURE"}
    return {"name": name, "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": pk}


def projects(fx: Fx) -> None:
    """每种锁文件一个项目。"""
    P = "~/Projects/"
    fx.json(P + "web-app/package-lock.json", npm_lock({
        "node_modules/evil-stealer": "3.2.1",                       # 名单上所有版本
        "node_modules/@fixture/evil-utils": "1.0.2",                # 带 scope、版本对
        "node_modules/fixture-colors": "1.4.0",                     # 版本不在名单上
        "node_modules/react": "18.3.1",
    }))
    fx.json(P + "web-app/node_modules/evil-stealer/package-lock.json", npm_lock({"node_modules/fixture-colors": "1.4.1"}))  # node_modules 里面：不看
    fx.file(P + "pnpm-site/pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n"
            "      fixture-colors:\n        specifier: 1.4.1\n        version: 1.4.1\n\npackages:\n\n"
            "  fixture-colors@1.4.1:\n    resolution: {integrity: sha512-FIXTURE}\n\n"
            "  '@fixture/evil-utils@1.0.3':\n    resolution: {integrity: sha512-FIXTURE}\n\n"
            "snapshots:\n\n  fixture-colors@1.4.1: {}\n\n  '@fixture/evil-utils@1.0.3': {}\n")
    fx.file(P + "yarn-classic/yarn.lock", "# yarn lockfile v1\n\n\n"
            "\"@fixture/evil-utils@^1.0.0\":\n  version \"1.0.1\"\n  resolved \"https://registry.yarnpkg.com/@fixture/evil-utils/-/evil-utils-1.0.1.tgz#abc\"\n\n"
            "react@^18.0.0:\n  version \"18.3.1\"\n")
    fx.file(P + "yarn-berry/yarn.lock", "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
            "\"evil-stealer@npm:^3.0.0\":\n  version: 3.0.0\n  resolution: \"evil-stealer@npm:3.0.0\"\n  languageName: node\n  linkType: hard\n\n"
            "\"yarn-berry@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"yarn-berry@workspace:.\"\n")
    fx.file(P + "bun-app/bun.lock", '{\n  "lockfileVersion": 1,\n  "workspaces": {\n    "": {\n      "name": "bun-app",\n'
            '      "dependencies": {\n        "fixture-colors": "1.4.1",\n      },\n    },\n  },\n  "packages": {\n'
            '    "fixture-colors": ["fixture-colors@1.4.1", "", {}, "sha512-FIXTURE"],\n  }\n}\n')
    fx.file(P + "py-uv/uv.lock", 'version = 1\nrequires-python = ">=3.12"\n\n[[package]]\nname = "py-uv"\nversion = "0.1.0"\n'
            'source = { editable = "." }\ndependencies = [\n    { name = "evil-requests" },\n]\n\n'
            '[[package]]\nname = "evil-requests"\nversion = "2.31.1"\nsource = { registry = "https://pypi.org/simple" }\n')
    fx.file(P + "py-poetry/poetry.lock", '[[package]]\nname = "Fixture.Setup_Tools"\nversion = "0.0.9"\noptional = false\n'
            'python-versions = "*"\n\n[[package]]\nname = "evil-requests"\nversion = "2.31.0"\noptional = false\n'
            'python-versions = "*"\n\n[metadata]\nlock-version = "2.0"\n')
    fx.json(P + "py-pipenv/Pipfile.lock", {"_meta": {"pipfile-spec": 6, "sources": []},
                                            "default": {"evil-requests": {"git": "https://example.invalid/evil.git"}},
                                            "develop": {"fixture-setup-tools": {"version": "==1.0.0"}}})
    fx.file(P + "rust-tool/crates/cli/Cargo.lock", 'version = 3\n\n[[package]]\nname = "evil-crate"\nversion = "0.3.2"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
            '[[package]]\nname = "evil_crate"\nversion = "0.3.5"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
    fx.json(P + "deep/a/b/c/d/package-lock.json", npm_lock({"node_modules/evil-stealer": "1.0.0"}))   # 往下四层：不找
    fx.json(P + "clean/package-lock.json", npm_lock({"node_modules/react": "18.3.1"}))
    fx.json(P + "web-app/test/fixtures/package-lock.json", npm_lock({"node_modules/evil-stealer": "1.0.0"}))   # 测试数据：不找
    fx.json(P + "web-app/examples/demo/package-lock.json", npm_lock({"node_modules/evil-stealer": "1.0.1"}))  # 示例：不找
    # 名字和名单上的一样、但是从 git、本地文件装的：不是那个包，不报。
    git_lock = npm_lock({})
    git_lock["packages"]["node_modules/evil-stealer"] = {"version": "3.2.1", "resolved": "git+ssh://git@github.com/acme/evil-stealer.git#0123abcd"}
    git_lock["packages"]["node_modules/fixture-colors"] = {"version": "1.4.1", "resolved": "file:vendor/fixture-colors-1.4.1.tgz"}
    fx.json(P + "own-forks/package-lock.json", git_lock)
    fx.file(P + "own-forks-yarn/yarn.lock", "# yarn lockfile v1\n\n\n"
            "evil-stealer@github:acme/evil-stealer#v3:\n  version \"3.2.1\"\n  resolved \"https://codeload.github.com/acme/evil-stealer/tar.gz/abc\"\n\n"
            "fixture-colors@file:./vendor/fixture-colors:\n  version \"1.4.1\"\n")
    # 公司自己的源上的同名包：照报，写明来自哪里。
    priv = npm_lock({})
    priv["packages"]["node_modules/@fixture/evil-utils"] = {"version": "1.0.1",
                                                          "resolved": "https://npm.acme.example/@fixture/evil-utils/-/evil-utils-1.0.1.tgz"}
    fx.json(P + "internal-app/package-lock.json", priv)


@case("rules/supplychain.malicious/no-list", "项目里有锁文件、还没导入过恶意包名单：什么也不说（不记成没扫描），名单能同步之前大多数 Mac 都没有")
def no_list(r: Run) -> None:
    projects(r.fx)
    r.update()
    r.scan(T0)


@case("rules/supplychain.malicious/lockfiles", "九种锁文件里名单上的包：所有版本、带 scope 的、PyPI 的名字写法不同、范围、私有源上的同名包（写明来源）；版本不对的、git 和本地文件的、node_modules 里面的、测试数据和示例里的、太深的不报")
def lockfiles(r: Run) -> None:
    projects(r.fx)
    import_list(r, standard_list(r.fx))
    r.update()
    r.scan(T0)
    r.scan(T0, "--no-full-disk-access", note="没有完全磁盘访问：~/Projects 不在要问的地方，照查")


@case("rules/supplychain.malicious/global", "全局装的包：Homebrew 和 /usr/local 的 npm（照 npm i -g 的样子：包自己的 node_modules 一层层往下，带 scope 的写全名）、nvm、pipx、uv tool、cargo install、bun 的全局锁文件；npm link 和 node_modules 里的链接不跟")
def global_installs(r: Run) -> None:
    fx = r.fx
    fx.json("opt-homebrew/lib/node_modules/evil-stealer/package.json", {"name": "evil-stealer", "version": "0.0.1"})
    fx.json("opt-homebrew/lib/node_modules/npm/package.json", {"name": "npm", "version": "10.8.0"})
    # npm i -g 的样子：没有锁文件，依赖装在包自己的 node_modules 里，有嵌套、有 scope、.bin 里是链接。
    G = "opt-homebrew/lib/node_modules/"
    fx.json(G + "good-cli/package.json", {"name": "good-cli", "version": "2.0.0", "bin": {"good": "cli.js"}})
    fx.json(G + "good-cli/node_modules/fixture-colors/package.json", {"name": "fixture-colors", "version": "1.4.1"})
    fx.json(G + "good-cli/node_modules/chalk/package.json", {"name": "chalk", "version": "5.3.0"})
    fx.json(G + "good-cli/node_modules/chalk/node_modules/evil-stealer/package.json", {"name": "evil-stealer", "version": "2.0.0"})
    fx.link(G + "good-cli/node_modules/.bin/colors", "../fixture-colors/cli.js")
    fx.json("elsewhere/evil-dep/package.json", {"name": "evil-stealer", "version": "8.8.8"})
    fx.link(G + "good-cli/node_modules/linked-dep", fx.p("elsewhere/evil-dep"))      # 链接：不跟
    fx.json(G + "@fixture-org/agent-cli/package.json", {"name": "@fixture-org/agent-cli", "version": "1.2.0"})
    fx.json(G + "@fixture-org/agent-cli/node_modules/@fixture/evil-utils/package.json", {"name": "@fixture/evil-utils", "version": "1.0.2"})
    fx.json("usr-local/lib/node_modules/@fixture/evil-utils/package.json", {"name": "@fixture/evil-utils", "version": "1.0.1"})
    fx.json("~/.nvm/versions/node/v22.0.0/lib/node_modules/fixture-colors/package.json", {"name": "fixture-colors", "version": "1.4.1"})
    fx.json("elsewhere/linked-evil/package.json", {"name": "evil-stealer", "version": "9.9.9"})
    fx.link("~/.nvm/versions/node/v22.0.0/lib/node_modules/linked-evil", fx.p("elsewhere/linked-evil"))   # npm link：不跟
    site = "lib/python3.12/site-packages/"
    fx.dir("~/.local/pipx/venvs/fixture-cli/" + site + "evil_requests-2.31.1.dist-info")
    fx.dir("~/.local/pipx/venvs/fixture-cli/" + site + "certifi-2024.2.2.dist-info")
    fx.dir("~/.local/share/uv/tools/other-cli/" + site + "fixture_setup_tools-3.0.0.dist-info")
    fx.json("~/.cargo/.crates2.json", {"installs": {
        "evil_crate 0.3.4 (registry+https://github.com/rust-lang/crates.io-index)": {"bins": ["evil"]},
        "evil_crate 0.3.4 (git+https://example.invalid/evil#abc)": {"bins": ["evil"]},
        "ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)": {"bins": ["rg"]}}})
    fx.file("~/.bun/install/global/bun.lock", '{"lockfileVersion": 1, "packages": {"@fixture/evil-utils": ["@fixture/evil-utils@1.0.2", "", {}, "sha512-FIXTURE"]}}')
    import_list(r, standard_list(fx))
    r.update()
    r.scan(T0)


@case("rules/supplychain.malicious/stale-list", "名单 40 天没更新：比对照做，另报一条名单旧了（仅供参考）")
def stale_list(r: Run) -> None:
    fx = r.fx
    fx.json("~/Projects/web-app/package-lock.json", npm_lock({"node_modules/evil-stealer": "3.2.1"}))
    import_list(r, standard_list(fx))
    r.update()
    r.scan(T0 + datetime.timedelta(days=35))


@case("cli/malicious-import", "导入恶意包名单：一个文件、一个 .zip（osv.dev 的导出）、文件夹；只留 MAL-，撤回的、别的生态的、没法比对的不留；每次导入加进原有的名单（同一编号的换新），各生态记各自的日期；出错时原来的名单保留")
def malicious_import(r: Run) -> None:
    fx = r.fx
    r.cli("malicious-import", "--data", fx.data)                                  # 没给路径
    r.cli("malicious-import", "--data", fx.data, fx.p("nowhere"))                 # 路径不在
    withdrawn = osv("MAL-2026-9101", "npm", "withdrawn-pkg", ["1.0.0"])
    withdrawn["withdrawn"] = "2026-10-16T00:00:00Z"
    one = fx.json("import/list.json", [
        osv("MAL-2026-9100", "npm", "one-file", ["1.0.0"], modified="2026-10-01T00:00:00Z"),
        withdrawn,
        osv("MAL-2026-9102", "RubyGems", "fixture-gem", ["1.0"]),
        osv("MAL-2026-9103", "npm", "no-versions"),
    ])
    r.cli("malicious-import", "--data", fx.data, one)
    zpath = fx.p("import/npm-all.zip")
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("MAL-2026-9200.json", json.dumps(osv("MAL-2026-9200", "npm", "zipped", all_versions=True, modified="2026-10-18T00:00:00Z")))
        z.writestr("GHSA-fixture-0002.json", json.dumps(osv("GHSA-fixture-0002", "npm", "lodash", ["4.17.20"])))
        z.writestr("notes.txt", "not read")
    r.cli("malicious-import", "--data", fx.data, zpath, note="加进原有的名单：one-file 还在")
    r.cli("malicious-import", "--data", fx.data, one, note="同一份再导一次：换掉同编号的那一条，不重复")
    fx.json("import/pypi/MAL-2026-9300.json", osv("MAL-2026-9300", "PyPI", "fixture-py", ["0.1.0"], modified="2026-10-05T00:00:00Z"))
    r.cli("malicious-import", "--data", fx.data, fx.p("import/pypi"), note="再导 PyPI：npm 的还在；名单日期取最旧的生态")
    fx.json("import/only-ghsa/GHSA-fixture-0003.json", osv("GHSA-fixture-0003", "npm", "lodash", ["4.17.20"]))
    fx.file("import/only-ghsa/broken.json", "{")
    r.cli("malicious-import", "--data", fx.data, fx.p("import/only-ghsa"), note="没有能用的：报错，原来的名单还在")
    fx.json("~/Projects/web-app/package-lock.json", npm_lock({"node_modules/zipped": "0.1.0", "node_modules/one-file": "1.0.0"}))
    r.update()
    r.scan(T0, note="名单是几次导入合起来的：zipped、one-file 都报")


@case("mcp/agent/malicious-package", "项目用了已知恶意的包：outbox 里是急事，卡片写清怎么办，只给「在访达里显示」和「处理好了」，不给删", quiet=False)
def agent_malicious_package(r: Run) -> None:
    fx = r.fx
    fx.json("~/Projects/web-app/package-lock.json", npm_lock({"node_modules/evil-stealer": "3.2.1", "node_modules/react": "18.3.1"}))
    import_list(r, standard_list(fx))
    r.update()
    r.scan(T0)
    a = Agent(r, T0 + datetime.timedelta(minutes=1))
    a.connect()
    a.look()
    item = a.item("security", "evil-stealer")
    a.click("scan_reveal", "在访达里显示", item=item)
    a.click("scan_ignore", "处理好了", item=item)
    a.read(OUTBOX)


@case("rules/supplychain.malicious/many-projects", "同一个恶意包用在 30 个项目里：只报一条，列出前 10 处和总数；名单上的包再多，单列 10 个，其余并成一条")
def many_projects(r: Run) -> None:
    fx = r.fx
    for i in range(30):
        fx.json(f"~/Projects/app{100 + i}/package-lock.json", npm_lock({"node_modules/evil-stealer": "3.2.1"}))
    records = [osv("MAL-2026-9001", "npm", "evil-stealer", all_versions=True)]
    others: Dict[str, str] = {}
    for i in range(12):
        records.append(osv(f"MAL-2026-95{i:02d}", "npm", f"fixture-bad-{i:02d}", all_versions=True))
        others[f"node_modules/fixture-bad-{i:02d}"] = "1.0.0"
    fx.json("~/Projects/zz-many/package-lock.json", npm_lock(others))
    import_list(r, osv_tree(fx, records))
    r.update()
    r.scan(T0)
