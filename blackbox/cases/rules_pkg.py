"""包管理器让依赖在安装时跑脚本（pkg.install-scripts，#107）：只看用着的工具、只认在磁盘上找到的版本、只读用户自己的配置；
「改成不跑」只往用户自己的配置末尾加一行，原来那份进废纸篓，放回时换回来。"""
from __future__ import annotations

import datetime

from agent import OUTBOX, Agent
from fx import T0, days
from harness import Run, case


def at(minutes: int) -> datetime.datetime:
    return T0 + datetime.timedelta(minutes=minutes)


def npm_project(r: Run) -> None:
    """一个 npm 装的项目：esbuild 有 postinstall，一个带 binding.gyp 的原生包，一个只有 test 脚本的；项目自己的 .npmrc 关了脚本。"""
    fx = r.fx
    fx.json("~/Projects/app/package.json", {"name": "app", "dependencies": {"esbuild": "^0.25.0"}})
    fx.json("~/Projects/app/package-lock.json", {"lockfileVersion": 3})
    fx.file("~/Projects/app/.npmrc", "ignore-scripts=true\n")
    fx.json("~/Projects/app/node_modules/esbuild/package.json", {"name": "esbuild", "scripts": {"postinstall": "node install.js"}})
    fx.json("~/Projects/app/node_modules/fsnative/package.json", {"name": "fsnative"})
    fx.file("~/Projects/app/node_modules/fsnative/binding.gyp", "{}\n")
    fx.json("~/Projects/app/node_modules/left-pad/package.json", {"name": "left-pad", "scripts": {"test": "node test.js"}})


@case("rules/pkg.install-scripts/npm", "npm 11 用着、~/.npmrc 没关：仅供参考一条（一项设置的现状，不指向哪个文件；标题是英文，证据只有代号和事实），带已装的依赖里要跑脚本的和放行的命令；项目自己的 .npmrc 不算")
def npm(r: Run) -> None:
    fx = r.fx
    fx.json("usr-local/lib/node_modules/npm/package.json", {"name": "npm", "version": "11.6.2"})
    fx.dir("~/.npm/_cacache", at=days(2))
    fx.file("~/.npmrc", "registry=https://registry.npmjs.org/\n# ignore-scripts=true\n", mode=0o600)
    npm_project(r)
    r.update()
    r.scan(T0)


@case("rules/pkg.install-scripts/not-reported", "不报的：npm 12（默认不跑）、~/.npmrc 关了的、没编译过源码包的 pip 和 uv、Yarn 4.14、装着没用过的 pnpm 8")
def not_reported(r: Run) -> None:
    fx = r.fx
    fx.json("~/.nvm/versions/node/v24.0.0/lib/node_modules/npm/package.json", {"name": "npm", "version": "12.1.0"})
    fx.dir("~/.npm/_cacache", at=days(2))
    fx.dir("~/Library/Caches/pip/http", at=days(2))
    fx.dir("~/.cache/uv/wheels-v5/pypi", at=days(2))
    fx.file("~/.yarnrc.yml", "nodeLinker: node-modules\n")
    fx.json("~/Projects/web/package.json", {"name": "web", "packageManager": "yarn@4.14.0"})
    fx.json("opt-homebrew/lib/node_modules/pnpm/package.json", {"name": "pnpm", "version": "8.15.0"})   # 装着，但没用过（没有它的配置、仓库、缓存）
    r.update()
    r.scan(T0)
    fx.json("usr-local/lib/node_modules/npm/package.json", {"name": "npm", "version": "10.9.0"})
    fx.file("~/.npmrc", "ignore-scripts = \"true\" ; 自己关的\n", mode=0o600)
    r.note("又装了 npm 10，但 ~/.npmrc 里关了")
    r.scan(at(60))


@case("rules/pkg.install-scripts/tools", "pnpm 9 的仓库、Yarn 4.5 的项目、pip 和 uv 编译过源码包：各一条；uv.toml 里有 [表]、pnpm 只能升级：不给「改成不跑」")
def tools(r: Run) -> None:
    fx = r.fx
    fx.dir("~/Library/pnpm/store/v3/files", at=days(5))
    fx.file("~/.yarnrc.yml", "npmRegistryServer: \"https://registry.yarnpkg.com\"\n")
    fx.json("~/Projects/web/package.json", {"name": "web", "packageManager": "yarn@4.5.0"})
    fx.file("~/Library/Caches/pip/wheels/3f/a1/pycrypto-2.6.1-cp312-cp312-macosx_14_0_arm64.whl", size=4096, at=days(9))
    fx.dir("~/.cache/uv/sdists-v9/pypi/pyyaml/6.0", at=days(4))
    fx.file("~/.config/uv/uv.toml", "[pip]\nindex-url = \"https://pypi.org/simple\"\n")
    r.update()
    r.scan(T0)


@case("mcp/apply/scripts-off", "「改成不跑」：~/.npmrc 末尾加一行（权限照旧，原来那份进废纸篓）、没有 pip.conf 就新建；下一轮不再报；放回换回原来的、新建的移走")
def apply_scripts_off(r: Run) -> None:
    fx = r.fx
    fx.json("usr-local/lib/node_modules/npm/package.json", {"name": "npm", "version": "11.6.2"})
    fx.dir("~/.npm/_cacache", at=days(2))
    fx.file("~/.npmrc", "registry=https://registry.npmjs.org/", mode=0o600)
    npm_project(r)
    fx.file("~/Library/Caches/pip/wheels/3f/a1/pycrypto-2.6.1-cp312-cp312-macosx_14_0_arm64.whl", size=4096, at=days(9))
    r.update()
    r.scan(T0)
    a = Agent(r, at(1))
    a.read(OUTBOX)
    a.read("page/overview")   # 改选项在扫描页上（卡片上只有「清理」）
    a.at(at(2)).click("scan_apply", "按上面的选择清理", page="overview", choose={"npm": "scripts-off", "pip": "scripts-off"})
    a.read("page/cleaned")
    r.scan(at(30), note="下一轮：两条都不报了")
    a.at(at(40)).read("page/cleaned")
    a.click("scan_restore", page="cleaned")
    r.scan(at(60), note="放回以后又报")


@case("mcp/apply/scripts-off-changed", "「改成不跑」点之前 ~/.npmrc 被换掉、改过以后用户又加了一行：不动换掉的；放回时留着用户的，原来那份放旁边")
def apply_scripts_off_changed(r: Run) -> None:
    fx = r.fx
    fx.json("usr-local/lib/node_modules/npm/package.json", {"name": "npm", "version": "11.6.2"})
    fx.dir("~/.npm/_cacache", at=days(2))
    fx.file("~/.npmrc", "registry=https://registry.npmjs.org/\n", mode=0o600)
    r.update()
    r.scan(T0)
    a = Agent(r, at(1))
    a.read(OUTBOX)
    a.read("page/overview")
    fx.remove("~/.npmrc")
    fx.file("~/.npmrc", "registry=https://npm.example.invalid/\n", mode=0o600, at=at(1))
    r.note("点之前 ~/.npmrc 删了重写（不是查的那一个了）")
    a.at(at(2)).click("scan_apply", "按上面的选择清理", page="overview", choose={"npm": "scripts-off"})
    r.scan(at(10))
    b = Agent(r, at(11))
    b.read(OUTBOX)
    b.read("page/overview")
    b.at(at(12)).click("scan_apply", "按上面的选择清理", page="overview", choose={"npm": "scripts-off"})
    fx.file("~/.npmrc", "registry=https://npm.example.invalid/\nignore-scripts=true\nsave-exact=true\n", mode=0o600, at=at(13))
    r.note("改好以后用户又加了一行 save-exact=true")
    b.at(at(14)).read("page/cleaned")
    b.click("scan_restore", page="cleaned")
