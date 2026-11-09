#!/usr/bin/env python3
"""打包螺壳扫描，给螺壳.app 带上（顶层 ADR 0022 的 11-05 修订：自家应用打进螺壳.app、跟螺壳一起升级和签名，不生成任何 .app）：
编 Go 版、带上 ClamAV 和 YARA、临时签名，摆成螺壳.app 的 Contents 下的样子，最后核对。

    python3 scripts/package_app.py [--out build.noindex] [--tools-from /opt/homebrew] [--tarball] [--without-virus-db]
    python3 scripts/package_app.py --verify <某个 luoke-scan 文件夹>      # 只核对一个打好的
    python3 scripts/package_app.py --verify-app <螺壳.app>                # 核对螺壳.app 里扫描的那些（正式签名以后也跑）

<out>/luoke-scan/ 里是什么，luoke-core 的 app/build_app.sh（LUOKE_SCAN_SRC）原样拷进螺壳.app 的 Contents：
  Helpers/luoke-scan          主程序（ai.luoke.scan）：读磁盘的是它，由螺壳本体起，用螺壳的「完全磁盘访问」；给 agent 的 MCP 走
                              本体交来的标准输入输出（luoke-scan mcp），从不开 socket。程序里编进了：
                                Info.plist（__TEXT,__info_plist：标识和版本号），签名盖住它，本体从签名信息读版本；
                                三个生成任务的提示词（照搬 prompts/，和评测用的逐字节一样）；
                                freshclam.conf（更新病毒库时写进这一次新建的 700 临时目录给 freshclam 读）；
                                ClamAV 的根证书（照 --tools-from 的 etc/clamav/certs）：ClamAV 1.5 找不到它就一个库都不读，
                                默认的文件夹只有装了 Homebrew ClamAV 的 Mac 才有；用时写进临时目录，--cvdcertsdir 指过去
  Helpers/luoke-scan-admin    删系统目录里的残留时，经 macOS 的密码框以 root 跑的那一步；root 先核对它的签名（ai.luoke.scan.admin）
  Helpers/clamscan freshclam sigtool yara   照 --tools-from 里装好的拷进来（ai.luoke.scan.<名字>）；luoke-scan 每次用之前
                              核对签名（标识和发行的团队），不对就当没有
  Frameworks/                 它们要的动态库（系统没有的那些），路径改成 @rpath（工具的 rpath 是 @executable_path/../Frameworks）
  Resources/scan/             luoke-accessory.json（配件清单，去掉草案标记）、bundled-tools.json（带进来的每个程序和库：版本、
                              来源、SHA-256）、AppIcon.icns
  Resources/licenses/luoke-scan/   ClamAV（GPLv2）、YARA 和各个库的许可证；THIRD-PARTY.md 是第三方说明：每个组件的版本、许可证、
                              包里的哪些文件、源码在哪（照 Homebrew 记的 sbom.spdx.json），以及 ClamAV 完整的对应源码在哪
Helpers 里只放程序（放别的文件，螺壳外层的签名会失败），数据都在 Resources 下。

签名：这里只做临时签名，定好各程序的标识（工具不开 hardened runtime：临时签名没有团队，库校验会拦下临时签名的库；正式签名时
luoke-core 的 tools/release_sign.sh 统一加上 hardened runtime，保留标识）。螺壳外层签名不能用 --deep，不然标识被盖掉，root 那一步
和 luoke-scan 都认不出来。LUOKE_RELEASE_TEAM：root 那一步和起扫描工具前核对签名用的团队标识，编进 luoke-scan（-ldflags -X），
源码里不写。

核对（每次打包后都跑；--verify、--verify-app 单独跑）：只有上面这些、没有链接；每个程序和库签名完整、标识对、没有 get-task-allow，
正式签名的要 hardened runtime、和螺壳同一个团队、不带「可以载入别人签的库」；luoke-scan 编进的 Info.plist、提示词、
freshclam.conf、根证书都在，和仓库里的一样；没有指向包外（/opt/homebrew 之类）的库路径和 rpath；包里的第三方库只有 ALLOWED 里
列的那些（新加一个要先改这张表，即「不加第三方包」）；包里每个第三方文件都写进了第三方说明；再在读不到 Homebrew（/opt/homebrew、
/usr/local）的条件下，四个工具都要跑得起来（freshclam 用 luoke-scan 自带的 freshclam.conf，不读 Homebrew 的），用包里的
clamscan（自带的一行测试库和这台机器的病毒库各一遍）和 YARA 对一个 EICAR 测试文件真扫一遍、用包里的 sigtool 读一遍库，要认得出来
（证书用从 luoke-scan 里取出来的那份）；这台机器没有病毒库就核对不过，不再跳过（只有 --without-virus-db 不核这一项，输出里写明）；包里的 luoke-scan 不收开发参数。只用标准库。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FOLDER = "luoke-scan"          # <out>/luoke-scan: laid out as 螺壳.app's Contents
HELPERS, FRAMEWORKS = "Helpers", "Frameworks"
RES = os.path.join("Resources", "scan")
LIC = os.path.join("Resources", "licenses", "luoke-scan")
ICON_NAME = "AppIcon.icns"
ICON = os.path.join(ROOT, "packaging", ICON_NAME)
BUNDLE_ID = "ai.luoke.scan"
OURS = ["luoke-scan", "luoke-scan-admin"]
IDENTIFIERS = {"luoke-scan": BUNDLE_ID, "luoke-scan-admin": f"{BUNDLE_ID}.admin"}
TOOLS = ["clamscan", "freshclam", "sigtool", "yara"]
# ClamAV opens its RAR support itself at run time (dlopen), so nothing links to these two. It looks in LD_LIBRARY_PATH
# (its own lookup, which the hardened runtime leaves alone) under the plain name: luoke-scan points it at Frameworks/.
LOADED_LATER = {"libclamunrar_iface.12.dylib": "libclamunrar_iface.dylib", "libclamunrar.12.dylib": "libclamunrar.12.dylib"}
# The only third-party code allowed in the package, by file name prefix. A new one fails `verify` until it is added here.
ALLOWED = ["libclamav.", "libclammspack.", "libfreshclam.", "libclamunrar", "libpcre2-8.", "libjson-c.", "libssl.",
           "libcrypto.", "libmagic.", "libjansson."]
LICENSES = {"clamav": ["COPYING.txt"], "yara": ["COPYING"], "pcre2": ["LICENCE.md"], "json-c": ["COPYING"],
            "openssl@4": ["LICENSE.txt"], "libmagic": ["COPYING"], "jansson": ["LICENSE"]}
# Licences Homebrew does not install, kept in packaging/third-party/<formula>/: ClamAV's COPYING/ folder (UnRAR, libmspack
# under the LGPL, bzip2, zlib and the rest it builds in) from the source of the version named here.
THIRD_PARTY = os.path.join(ROOT, "packaging", "third-party")
# The generate tasks' prompts: luoke-scan carries what the release eval measured (assets.go), so they go in as they are.
PROMPTS = os.path.join(ROOT, "prompts")
FRESHCLAM_CONF = os.path.join(ROOT, "packaging", "freshclam.conf")
# ClamAV's root certificate is copied here before building, for assets.go to put it inside luoke-scan; only the README
# is in git.
CERTS_STAGE = os.path.join(ROOT, "packaging", "clamav-certs")
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?")
# The smoke test runs the packed tools where they cannot read Homebrew, as on a Mac without it.
NO_HOMEBREW = '(version 1)(allow default)(deny file-read* file-read-metadata (subpath "/opt/homebrew") (subpath "/usr/local"))'
CLAMAV_COPYING_FROM = "1.5.4"
# ClamAV's complete corresponding source goes on 螺壳's releases (GPLv2 §3(a)): the release that first carries a ClamAV
# version also carries upstream's source tarball, the Homebrew formula it was built with and the formula's patches; later
# releases with the same version point back to it. The publishing pipeline keeps this index (ClamAV version → links)
# up to date; the notice points at it (and its mirror).
SOURCE_INDEX = "https://github.com/luokelabs/luoke-releases/blob/main/licenses/clamav/README.md"
SOURCE_INDEX_MIRROR = "https://gitlab.com/luokelabs/luoke-releases/-/blob/main/licenses/clamav/README.md"
NOTICE = "THIRD-PARTY.md"
SYSTEM = ("/usr/lib/", "/System/Library/")
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def run(cmd: list[str], **kw) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise SystemExit(f"{' '.join(cmd[:3])}… 退出码 {r.returncode}：{(r.stderr or r.stdout).strip()[-1500:]}")
    return r.stdout


def is_macho(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(4) in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")


def deps(path: str) -> list[str]:
    """The libraries a Mach-O loads (its own id left out)."""
    out = run(["otool", "-L", path]).splitlines()[1:]
    names = [l.strip().split(" (")[0] for l in out if l.strip()]
    own = run(["otool", "-D", path]).splitlines()[1:]
    return [n for n in names if n not in own]


def rpaths(path: str) -> list[str]:
    out = run(["otool", "-l", path])
    return re.findall(r"cmd LC_RPATH\n\s+cmdsize \d+\n\s+path (.+?) \(offset", out)


def resolve(dep: str, binary: str) -> str | None:
    """Where a dependency of `binary` is on this Mac (to copy it), following @rpath, @loader_path and links."""
    if dep.startswith("@rpath/"):
        for rp in rpaths(binary):
            p = os.path.join(rp.replace("@loader_path", os.path.dirname(binary)).replace("@executable_path", os.path.dirname(binary)),
                             dep[len("@rpath/"):])
            if os.path.exists(p):
                return os.path.realpath(p)
        p = os.path.join(os.path.dirname(binary), dep[len("@rpath/"):])   # what loads it usually sits next to it
        return os.path.realpath(p) if os.path.exists(p) else None
    if dep.startswith("@loader_path/"):
        p = os.path.join(os.path.dirname(binary), dep[len("@loader_path/"):])
        return os.path.realpath(p) if os.path.exists(p) else None
    return os.path.realpath(dep) if os.path.exists(dep) else None


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def formula_of(path: str) -> tuple[str, str]:
    """(formula, version) for a file in the Homebrew Cellar, else ("", "")."""
    m = re.search(r"/Cellar/([^/]+)/([^/]+)/", path)
    return (m.group(1), m.group(2)) if m else ("", "")


def cellar_info(path: str) -> dict:
    """What Homebrew recorded about the formula a file came from: version, licence and where its source is (the keg's
    sbom.spdx.json), and the homebrew-core commit it was installed from (INSTALL_RECEIPT.json), for the build recipe."""
    m = re.search(r"^(.*/Cellar/([^/]+)/([^/]+))/", path)
    if not m:
        raise SystemExit(f"{path} 不是从 Homebrew 装的：说不清它的许可证和源码在哪")
    keg, formula, version = m.groups()
    try:
        with open(os.path.join(keg, "sbom.spdx.json"), encoding="utf-8") as f:
            pkg = next(p for p in json.load(f)["packages"] if p.get("name") == formula)
        with open(os.path.join(keg, "INSTALL_RECEIPT.json"), encoding="utf-8") as f:
            head = (json.load(f).get("source") or {}).get("tap_git_head")
    except (OSError, ValueError, KeyError, StopIteration):
        raise SystemExit(f"{keg} 里读不到 Homebrew 的 sbom.spdx.json 或 INSTALL_RECEIPT.json：说不清 {formula} 的许可证和源码在哪")
    licence, source = pkg.get("licenseConcluded"), pkg.get("downloadLocation")
    if not licence or licence == "NOASSERTION" or not source or source == "NOASSERTION":
        raise SystemExit(f"Homebrew 没记 {formula} 的许可证或源码地址（{keg}/sbom.spdx.json）")
    shard = "lib" if formula.startswith("lib") else formula[0]   # how homebrew-core lays out Formula/
    recipe = f"https://github.com/Homebrew/homebrew-core/blob/{head}/Formula/{shard}/{formula}.rb" if head else ""
    return {"formula": formula, "version": pkg.get("versionInfo") or version, "licence": licence, "source": source,
            "recipe": recipe}


def write_notice(path: str, provenance: list[tuple[str, str]]) -> None:
    """The third-party notice: each component, its version and licence, which files in the package are its, where its source
    is, Homebrew's build recipe when it is known, and where ClamAV's complete corresponding source is (`SOURCE_INDEX`)."""
    comps: dict[str, dict] = {}
    for name, src in provenance:
        if name in OURS:
            continue
        info = cellar_info(src)
        comps.setdefault(info["formula"], {**info, "files": []})["files"].append(name)
    clamav = comps.get("clamav", {}).get("version", "")
    if clamav and clamav != CLAMAV_COPYING_FROM:
        log(f"注意：包里的 ClamAV 是 {clamav}，packaging/third-party/clamav/ 是从 {CLAMAV_COPYING_FROM} 的源码取的，"
            f"核对一下 clamav-{clamav} 源码包的 COPYING/ 有没有变，再改 CLAMAV_COPYING_FROM")
    lines = ["# 螺壳扫描带的第三方组件", "",
             "下面这些程序和库是别人写的开源软件，从 Homebrew 装好的版本原样拷进来；只改了库的查找路径（install_name_tool），"
             "再重新签名，代码没有改动。螺壳扫描自己的两个程序（luoke-scan、luoke-scan-admin）都不链接"
             "它们的库：clamscan、freshclam、sigtool 和 yara 只由 luoke-scan 用命令行起。", "",
             "| 组件 | 版本 | 许可证 | 包里的文件 |", "|---|---|---|---|"]
    for c in comps.values():
        lines.append(f"| {c['formula']} | {c['version']} | {c['licence']} | {', '.join(sorted(c['files']))} |")
    lines += ["", "## 源码", ""]
    for c in comps.values():
        lines.append(f"- {c['formula']} {c['version']}：{c['source']}")
        if c["formula"] == "clamav" and c["recipe"]:
            lines.append(f"  - Homebrew 编它用的构建方法：{c['recipe']}")
    if clamav:
        lines += ["", "## ClamAV 完整的对应源码", "",
                  f"ClamAV 是 GPLv2。包里 ClamAV {clamav} 完整的对应源码（上游的源码包，连同它编进去的 UnRAR、libmspack 等"
                  "代码；Homebrew 编它用的 formula 和 formula 打的补丁）挂在螺壳的发布上，哪一版挂在哪里见这份索引："
                  f"<{SOURCE_INDEX}>（镜像：<{SOURCE_INDEX_MIRROR}>）。"]
    lines += ["", "## 许可证全文", "",
              "在本文件旁边，按组件分目录。ClamAV 的 `clamav/COPYING.txt` 是 GPLv2，带一条允许和 OpenSSL 链接的例外；"
              f"`clamav/COPYING.*` 取自 ClamAV {CLAMAV_COPYING_FROM} 源码包的 `COPYING/` 目录，是它编进去的 UnRAR、"
              "libmspack（LGPL）、bzip2、zlib 等代码的许可证。", ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))




# ---------------------------------------------------------------- building

def manifest_from_repo() -> dict:
    with open(os.path.join(ROOT, "packaging", "luoke-accessory.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    manifest.pop("_draft", None)
    return manifest


def info_plist(name: str, version: str) -> bytes:
    """The Info.plist linked into each of our programs (__TEXT,__info_plist): the signature covers it, so luoke's main
    app reads the version from the signature (kSecCodeInfoPList) and an older build cannot pass for a newer one."""
    return plistlib.dumps({"CFBundleIdentifier": IDENTIFIERS[name], "CFBundleName": name, "CFBundleInfoDictionaryVersion": "6.0",
                           "CFBundleShortVersionString": version, "CFBundleVersion": version})


def stage_certs(tools_from: str) -> list[str]:
    """ClamAV's root certificate into packaging/clamav-certs, for the build to put inside luoke-scan."""
    certs_from = os.path.join(tools_from, "etc", "clamav", "certs")
    crts = sorted(n for n in os.listdir(certs_from) if n.endswith(".crt")) if os.path.isdir(certs_from) else []
    if not crts:
        raise SystemExit(f"{certs_from} 里没有 ClamAV 的根证书（brew install clamav 时装上的）：没有它，包里的 ClamAV "
                         "在没装 Homebrew ClamAV 的 Mac 上一个病毒库都读不了")
    unstage_certs()
    for n in crts:
        shutil.copyfile(os.path.join(certs_from, n), os.path.join(CERTS_STAGE, n))
    return [os.path.realpath(os.path.join(certs_from, n)) for n in crts]


def unstage_certs() -> None:
    for n in os.listdir(CERTS_STAGE):
        if n.endswith(".crt"):
            os.remove(os.path.join(CERTS_STAGE, n))


def build(tools_from: str) -> tuple[str, list[str]]:
    """The two programs, built with Go into build.noindex/go-bin: luoke-scan marked as the packed copy (it then takes
    no development flags), with the release's team for the signature checks, and with ClamAV's certificate inside;
    each with its Info.plist linked in."""
    log("== go build")
    go = os.environ.get("GO") or shutil.which("go") or next((g for g in ("/usr/local/go/bin/go", "/opt/homebrew/bin/go") if os.access(g, os.X_OK)), "go")
    out = os.path.join(ROOT, "build.noindex", "go-bin")
    os.makedirs(out, exist_ok=True)
    version = manifest_from_repo()["version"]
    pkg = "github.com/luokelabs/luoke-scan/internal/core"
    flags = f"-X {pkg}.packedFlag=1"
    team = os.environ.get("LUOKE_RELEASE_TEAM", "")
    if team:
        if not re.fullmatch(r"[A-Z0-9]{10}", team):
            raise SystemExit("LUOKE_RELEASE_TEAM 要是十位的团队标识")
        flags += f" -X {pkg}.ReleaseTeam={team}"
    else:
        log("（没给 LUOKE_RELEASE_TEAM：root 那一步和扫描工具只核标识、不核团队，这个包删不了系统目录里的东西）")
    # cgo (FSEvents, the keyboard taps, the volume's capacity) with Apple's own compiler: a swiftly or other toolchain
    # first on PATH may answer for "clang".
    env = {**os.environ, "CGO_ENABLED": "1", "GOOS": "darwin", "GOARCH": "arm64",
           "CC": os.environ.get("CC") or ("/usr/bin/clang" if os.path.exists("/usr/bin/clang") else "clang")}
    certs = stage_certs(tools_from)
    try:
        for name, ldflags in (("luoke-scan", flags), ("luoke-scan-admin", "")):
            plist = os.path.join(out, f"{name}.Info.plist")
            with open(plist, "wb") as f:
                f.write(info_plist(name, version))
            ldflags += f" -linkmode=external -extldflags '-Wl,-sectcreate,__TEXT,__info_plist,{plist}'"
            run([go, "build", "-trimpath", "-ldflags", ldflags.strip(), "-o", os.path.join(out, name), f"./cmd/{name}"],
                cwd=ROOT, env=env)
    finally:
        unstage_certs()
    return out, certs


def assemble(bin_dir: str, out: str, tools_from: str, certs: list[str]) -> str:
    top = os.path.join(out, FOLDER)
    if os.path.exists(top):
        shutil.rmtree(top)
    helpers, fw, res, lic = (os.path.join(top, d) for d in (HELPERS, FRAMEWORKS, RES, LIC))
    for d in (helpers, fw, res, lic):
        os.makedirs(d)
    with open(os.path.join(res, "luoke-accessory.json"), "w", encoding="utf-8") as f:
        json.dump(manifest_from_repo(), f, ensure_ascii=False, indent=2)
        f.write("\n")
    shutil.copyfile(ICON, os.path.join(res, ICON_NAME))
    for name in OURS:
        shutil.copy2(os.path.join(bin_dir, name), os.path.join(helpers, name))
        # No debug info or local symbols in what ships (they name this machine's build folders); before signing. The
        # build in bin_dir keeps them, for dsymutil when a crash has to be symbolicated.
        run(["strip", "-S", "-x", os.path.join(helpers, name)])
    provenance = []
    for name in TOOLS:
        src = os.path.realpath(os.path.join(tools_from, "bin", name))
        if not os.path.exists(src):
            raise SystemExit(f"{tools_from}/bin 里没有 {name}（brew install clamav yara）")
        shutil.copy2(src, os.path.join(helpers, name))
        provenance.append((f"{HELPERS}/{name}", src))
    # Every library they need that the system does not have, and what those need in turn, under the name they are
    # asked for (libclamav.12.dylib, not the file that link points to).
    copied: dict[str, str] = {}   # name in Frameworks/ -> file on this Mac
    todo = [src for _, src in provenance]
    clamav_lib = os.path.dirname(resolve("@rpath/libclamav.12.dylib", provenance[0][1]) or "")
    for n, as_name in LOADED_LATER.items():
        if os.path.exists(os.path.join(clamav_lib, n)):
            copied[as_name] = os.path.realpath(os.path.join(clamav_lib, n))
            todo.append(copied[as_name])
    while todo:
        src = todo.pop()
        for d in deps(src):
            base = os.path.basename(d)
            if d.startswith(SYSTEM) or base in copied:
                continue
            found = resolve(d, src)
            if not found:
                raise SystemExit(f"{src} 要的 {d} 找不到")
            copied[base] = found
            todo.append(found)
    for name, src in sorted(copied.items()):
        shutil.copy2(src, os.path.join(fw, name))
        provenance.append((f"{FRAMEWORKS}/{name}", src))
    # Homebrew installs ClamAV's certificate under <prefix>/etc, outside the keg: it is counted under the keg of the
    # clamscan it was installed with (same formula, same version). It is inside luoke-scan.
    counted_as: dict[str, str] = {}   # file in the package -> the keg file it is counted under
    for c in certs:
        n = f"{HELPERS}/luoke-scan（ClamAV 根证书 {os.path.basename(c)}）"
        provenance.append((n, c))
        counted_as[n] = provenance[0][1]
    for formula, files in LICENSES.items():
        base = os.path.join(tools_from, "opt", formula)
        for f in files:
            if not os.path.exists(os.path.join(base, f)):
                raise SystemExit(f"{formula} 的许可证 {f} 找不到：GPL 的 ClamAV 和别的库都要附上许可证才能分发")
            os.makedirs(os.path.join(lic, formula), exist_ok=True)
            shutil.copy2(os.path.join(base, f), os.path.join(lic, formula, f))
    for formula in sorted(os.listdir(THIRD_PARTY)):
        for f in sorted(os.listdir(os.path.join(THIRD_PARTY, formula))):
            os.makedirs(os.path.join(lic, formula), exist_ok=True)
            shutil.copy2(os.path.join(THIRD_PARTY, formula, f), os.path.join(lic, formula, f))
    write_notice(os.path.join(lic, NOTICE), [(n, counted_as.get(n, s)) for n, s in provenance])
    with open(os.path.join(res, "bundled-tools.json"), "w", encoding="utf-8") as f:
        json.dump([{"file": n, "formula": formula_of(counted_as.get(n, s))[0], "version": formula_of(counted_as.get(n, s))[1],
                    "source": s, "sha256": sha256(s)} for n, s in provenance], f, ensure_ascii=False, indent=1)
        f.write("\n")
    return top


def relink(top: str) -> None:
    """Library paths into the bundle: the tools find their libraries in ../Frameworks, the libraries each other."""
    helpers, fw = os.path.join(top, HELPERS), os.path.join(top, FRAMEWORKS)
    bundled = set(os.listdir(fw))
    for d, files in ((helpers, TOOLS), (fw, sorted(bundled))):
        for name in files:
            p = os.path.join(d, name)
            os.chmod(p, 0o755)
            args = []
            if d == fw:
                args += ["-id", f"@rpath/{name}"]
            for dep in deps(p):
                base = os.path.basename(dep)
                if not dep.startswith(SYSTEM) and base in bundled:
                    args += ["-change", dep, f"@rpath/{base}"]
            want = f"@executable_path/../{FRAMEWORKS}" if d == helpers else "@loader_path"
            have = rpaths(p)
            for rp in have:
                if rp != want:
                    args += ["-delete_rpath", rp]
            if want not in have:
                args += ["-add_rpath", want]
            run(["install_name_tool"] + args + [p])


DEV_ENTITLEMENT = "com.apple.security.cs.disable-library-validation"


def sign(top: str) -> None:
    """Ad hoc, each program and library on its own, with the identifiers root and luoke-scan check (ai.luoke.scan.admin,
    ai.luoke.scan.<tool>). Our two programs with the hardened runtime; the four tools without it: an ad hoc signature has
    no team, and the runtime's library validation would refuse their ad hoc libraries. luoke-core's release_sign.sh
    signs them all again with the Developer ID and the runtime, keeping the identifiers."""
    base = ["codesign", "--force", "--sign", "-", "--timestamp=none"]
    fw, helpers = os.path.join(top, FRAMEWORKS), os.path.join(top, HELPERS)
    for name in sorted(os.listdir(fw)):
        run(base + [os.path.join(fw, name)])
    for name in TOOLS:
        run(base + ["--identifier", f"{BUNDLE_ID}.{name}", os.path.join(helpers, name)])
    for name in OURS:
        run(base + ["--options", "runtime", "--identifier", IDENTIFIERS[name], os.path.join(helpers, name)])


# ---------------------------------------------------------------- checking

def prompt_files() -> list[str]:
    return sorted(f for f in os.listdir(PROMPTS) if os.path.isfile(os.path.join(PROMPTS, f)) and not f.startswith("."))


def linked_plist(path: str) -> dict | None:
    """The Info.plist linked into a program (__TEXT,__info_plist), or None."""
    r = subprocess.run(["otool", "-X", "-s", "__TEXT", "__info_plist", path], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    raw = bytearray()
    for line in r.stdout.splitlines():
        words = line.split("\t", 1)[-1].split()
        try:
            raw += b"".join(bytes.fromhex(w)[::-1] if len(w) == 8 else bytes.fromhex(w) for w in words)
        except ValueError:
            return None
    try:
        return plistlib.loads(bytes(raw).rstrip(b"\0"))
    except Exception:
        return None


def carried_certs(program: str) -> list[bytes]:
    """The PEM certificates inside a program (luoke-scan carries ClamAV's: assets.go)."""
    with open(program, "rb") as f:
        return PEM.findall(f.read())


def signature(path: str) -> dict:
    """codesign -dvvv of a file: identifier, team (None for ad hoc), runtime flag, entitlements."""
    d = subprocess.run(["codesign", "-dvvv", path], capture_output=True, text=True).stderr
    ent = subprocess.run(["codesign", "-d", "--entitlements", "-", "--xml", path], capture_output=True, text=True).stdout
    ident = re.search(r"^Identifier=(.+)$", d, re.M)
    team = re.search(r"^TeamIdentifier=(\S+)$", d, re.M)
    return {"identifier": ident.group(1) if ident else "", "team": None if not team or team.group(1) == "not" else team.group(1),
            "runtime": bool(re.search(r"flags=0x[0-9a-f]*\(.*runtime.*\)", d)), "entitlements": ent}


def verify(root: str, in_app: bool = False, smoke: bool = True, need_db: bool = True) -> list[str]:
    """root is the folder this script makes (<out>/luoke-scan), or a built 螺壳.app's Contents (in_app): then only the
    scan's own files are looked at, and every signed one must be signed by 螺壳's own team."""
    bad: list[str] = []
    if os.path.islink(root) or not os.path.isdir(root):
        return [f"{root} 不是文件夹"]
    helpers, fw, res, lic = (os.path.join(root, d) for d in (HELPERS, FRAMEWORKS, RES, LIC))
    for p in [os.path.join(helpers, n) for n in OURS + TOOLS] + [os.path.join(res, n) for n in ("luoke-accessory.json", "bundled-tools.json", ICON_NAME)] + [lic]:
        if not os.path.exists(p):
            bad.append(f"少了 {os.path.relpath(p, root)}")
    if bad:
        return bad
    try:
        with open(os.path.join(res, "luoke-accessory.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        with open(os.path.join(res, "bundled-tools.json"), encoding="utf-8") as f:
            bundled = json.load(f)
    except (OSError, ValueError):
        return bad + ["配件清单或 bundled-tools.json 读不了"]
    libs = sorted(os.path.basename(t["file"]) for t in bundled if t["file"].startswith(FRAMEWORKS + "/"))
    if not in_app:
        layout = {"": {HELPERS, FRAMEWORKS, "Resources"}, HELPERS: set(OURS + TOOLS), FRAMEWORKS: set(libs),
                  "Resources": {"scan", "licenses"}, RES: {"luoke-accessory.json", "bundled-tools.json", ICON_NAME},
                  os.path.join("Resources", "licenses"): {"luoke-scan"}}
        for rel, want in layout.items():
            have = set(os.listdir(os.path.join(root, rel)))
            if have != want:
                bad.append(f"{rel or '最上层'} 里多了 {sorted(have - want)}，少了 {sorted(want - have)}")
    walk = [helpers, fw, res, lic] if in_app else [root]
    for top in walk:
        for dp, ds, fs in os.walk(top):
            for n in fs + ds:
                if os.path.islink(os.path.join(dp, n)):
                    bad.append(f"{os.path.relpath(os.path.join(dp, n), root)} 是链接：包里不放链接")
    app_team = None
    if in_app:
        app_team = signature(os.path.dirname(root.rstrip("/"))).get("team")
    machos = [os.path.join(helpers, n) for n in OURS + TOOLS] + [os.path.join(fw, n) for n in libs]
    for p in machos:
        rel = os.path.relpath(p, root)
        if not os.path.isfile(p):
            bad.append(f"少了 {rel}")
            continue
        if os.path.dirname(rel) == FRAMEWORKS and not os.path.basename(rel).startswith(tuple(ALLOWED)):
            bad.append(f"{rel} 不在允许的第三方库里（scripts/package_app.py 的 ALLOWED）")
        r = subprocess.run(["codesign", "--verify", "--strict", "--verbose=2", p], capture_output=True, text=True)
        if r.returncode != 0:
            bad.append(f"{rel} 签名不完整：{r.stderr.strip()[-300:]}")
            continue
        sig = signature(p)
        name = os.path.basename(p)
        want = IDENTIFIERS.get(name) or (f"{BUNDLE_ID}.{name}" if name in TOOLS else None)
        if want and sig["identifier"] != want:
            bad.append(f"{rel} 的签名标识是 {sig['identifier']}，不是 {want}")
        if "get-task-allow" in sig["entitlements"]:
            bad.append(f"{rel} 带着 get-task-allow")
        if DEV_ENTITLEMENT in sig["entitlements"]:
            bad.append(f"{rel} 带着 {DEV_ENTITLEMENT}")
        if sig["team"]:                      # signed for a release: what release_sign.sh made of it
            if not sig["runtime"]:
                bad.append(f"{rel} 是正式签名，却不是 hardened runtime")
            if in_app and sig["team"] != app_team:
                bad.append(f"{rel} 的团队和螺壳的不一样")
        elif in_app and app_team:
            bad.append(f"{rel} 没有正式签名，螺壳却是正式签名的")
        elif name in OURS and not sig["runtime"]:
            bad.append(f"{rel} 不是 hardened runtime")
        for dep in deps(p):
            if not (dep.startswith(SYSTEM) or dep.startswith("@rpath/") or dep.startswith("@loader_path/")
                    or dep.startswith("@executable_path/")):
                bad.append(f"{rel} 要包外的库 {dep}")
        for rp in rpaths(p):
            if not rp.startswith(("@executable_path", "@loader_path", "/usr/lib/swift")):
                bad.append(f"{rel} 的 rpath 指向包外：{rp}")
    for name in OURS:
        info = linked_plist(os.path.join(helpers, name)) or {}
        if info.get("CFBundleIdentifier") != IDENTIFIERS[name] or info.get("CFBundleShortVersionString") != manifest.get("version"):
            bad.append(f"{name} 编进的 Info.plist（{info.get('CFBundleIdentifier')} {info.get('CFBundleShortVersionString')}）"
                       f"和标识 {IDENTIFIERS[name]}、配件清单的版本 {manifest.get('version')} 对不上")
    if manifest.get("bundle_id") != BUNDLE_ID:
        bad.append(f"配件清单的 bundle_id 不是 {BUNDLE_ID}")
    with open(os.path.join(helpers, "luoke-scan"), "rb") as f:
        program = f.read()
    for name in prompt_files():
        with open(os.path.join(PROMPTS, name), "rb") as f:
            if f.read() not in program:
                bad.append(f"luoke-scan 里没有 prompts/{name}（或者和仓库里的不一样）")
    with open(FRESHCLAM_CONF, "rb") as f:
        if f.read() not in program:
            bad.append("luoke-scan 里没有 packaging/freshclam.conf（或者和仓库里的不一样）")
    if not carried_certs(os.path.join(helpers, "luoke-scan")):
        bad.append("luoke-scan 里没有 ClamAV 的根证书：没有它，包里的 ClamAV 在没装 Homebrew ClamAV 的 Mac 上读不了病毒库")
    if "_draft" in manifest:
        bad.append("配件清单还带着草案标记")
    if sha256(os.path.join(res, ICON_NAME)) != sha256(ICON):
        bad.append(f"{RES}/{ICON_NAME} 和 packaging/{ICON_NAME} 不一样")
    # The programs luoke-core starts by name: a bare name of one of ours in Helpers, no "/", not starting with ".".
    def program_ok(name) -> bool:
        return isinstance(name, str) and name in OURS
    for j in manifest.get("jobs", []):
        if not program_ok(j.get("exec")):
            bad.append(f"空闲任务 {j.get('name')} 的 exec（{j.get('exec')!r}）不是 Helpers 里我们的程序名")
    # capabilities.permissions is the one place that declares a permission; a job only names the ones it uses.
    declared = {p.get("id") for p in manifest.get("capabilities", {}).get("permissions", [])}
    for j in manifest.get("jobs", []):
        uses = j.get("uses", [])
        if not (isinstance(uses, list) and all(x in declared for x in uses)):
            bad.append(f"空闲任务 {j.get('name')} 的 uses（{uses!r}）不全是 capabilities.permissions 里的编号")
    for formula, files in LICENSES.items():
        for f in files:
            if not os.path.exists(os.path.join(lic, formula, f)):
                bad.append(f"少了 {formula} 的许可证 {f}")
    for formula in os.listdir(THIRD_PARTY):
        for f in os.listdir(os.path.join(THIRD_PARTY, formula)):
            if not os.path.exists(os.path.join(lic, formula, f)):
                bad.append(f"少了 {formula} 的许可证 {f}")
    notice = os.path.join(lic, NOTICE)
    if not os.path.exists(notice):
        bad.append(f"少了第三方说明 {LIC}/{NOTICE}")
    else:
        listed = set()   # the last column of the table: the files each component put in the package
        with open(notice, encoding="utf-8") as f:
            for line in f:
                cells = line.strip().strip("|").split("|")
                if line.startswith("| ") and not line.startswith(("| 组件", "|---")) and len(cells) == 4:
                    listed.update(n.strip() for n in cells[-1].split(","))
        for t in bundled:
            if t["file"] not in listed:
                bad.append(f"第三方说明里没写 {t['file']}")
    # The program with Full Disk Access takes no flag that points it at other programs or folders (review of #14).
    for cmd in (["update", "--this-mac", "--tool-dir", "/nonexistent", "--force"], ["scan", "--home", "/nonexistent"],
                ["mcp", "--fixture", "/nonexistent"], ["fixture", "/nonexistent"]):
        r = subprocess.run([os.path.join(helpers, "luoke-scan")] + cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 64:
            bad.append(f"包里的 luoke-scan 没拒绝开发参数：{' '.join(cmd)} 退出码 {r.returncode}")
    if smoke and not bad:
        bad += smoke_test(root, need_db)
    return bad


def smoke_test(root: str, need_db: bool = True) -> list[str]:
    """The packed tools on a fake download with an EICAR test file: the packed clamscan (with the packed RAR support and
    the certificate taken out of luoke-scan, as MalwareRule runs it) must recognise it, the packed sigtool must read the
    database (as VirusDB checks a new one) and the packed YARA must run a rule. Those three run where they cannot read
    Homebrew (NO_HOMEBREW), as on a Mac without it: the build machines have it, and ClamAV's default certificate folder
    is there. Not through the packed luoke-scan: it takes no --home / --data (review of #14), and --this-mac would read
    the real home. Uses the virus database of the Mac it runs on (cloned, not downloaded); without one it fails rather
    than skip the check (#99): run freshclam once on the build machine. Only --without-virus-db (the GitHub release,
    which downloads none) leaves that part out, and says so. The packed clamscan also scans the sample with a
    one-line hash database of its own, so that much never depends on the build machine.
    Every tool's --version runs away from Homebrew too, freshclam with luoke-scan's own freshclam.conf (as VirusDB runs
    it): without --config-file it reads Homebrew's, which a fresh Homebrew does not have (#98)."""
    helpers, fw = os.path.join(root, HELPERS), os.path.join(root, FRAMEWORKS)
    bad = []
    env = {"LD_LIBRARY_PATH": fw, "PATH": "/usr/bin:/bin"}
    sandbox = "/usr/bin/sandbox-exec"
    if not os.access(sandbox, os.X_OK):
        return bad + [f"没有 {sandbox}：核对不了包里的工具离了 Homebrew 能不能用"]
    away = [sandbox, "-p", NO_HOMEBREW]
    with tempfile.TemporaryDirectory(prefix="luoke-scan-ver-") as t:
        conf = os.path.join(t, "freshclam.conf")
        shutil.copyfile(FRESHCLAM_CONF, conf)
        for name in TOOLS:
            extra = [f"--config-file={conf}"] if name == "freshclam" else []
            r = subprocess.run(away + [os.path.join(helpers, name)] + extra + ["--version"], capture_output=True, text=True,
                               env=env, timeout=60)
            if r.returncode != 0 or not r.stdout.strip():
                bad.append(f"包里的 {name} 离了 Homebrew 跑不起来：{(r.stderr or r.stdout).strip()[-200:]}")
    with tempfile.NamedTemporaryFile(prefix="luoke-scan-rar-", suffix=".txt") as probe:
        r = subprocess.run([os.path.join(helpers, "clamscan"), "--debug", "--database=/dev/null", probe.name], capture_output=True,
                           text=True, env=env)
        if f"unrar support loaded from {fw}/" not in r.stdout + r.stderr:
            bad.append("包里的 clamscan 没载入包里的 RAR 支持（libclamunrar_iface.dylib）")
    db = next((d for d in ("/opt/homebrew/var/lib/clamav", "/usr/local/var/lib/clamav") if os.path.exists(os.path.join(d, "main.cld"))
               or os.path.exists(os.path.join(d, "main.cvd"))), None)
    with tempfile.TemporaryDirectory(prefix="luoke-scan-pack-") as t:
        certs_dir = os.path.join(t, "certs")
        os.makedirs(certs_dir)
        for i, pem in enumerate(carried_certs(os.path.join(helpers, "luoke-scan"))):
            with open(os.path.join(certs_dir, "clamav.crt" if i == 0 else f"clamav-{i}.crt"), "wb") as f:
                f.write(pem)
        certs = [f"--cvdcertsdir={certs_dir}"]
        sample = os.path.join(t, "eicar.com")
        with open(sample, "wb") as f:
            f.write(EICAR)
        rules = os.path.join(t, "t.yar")
        with open(rules, "w") as f:
            f.write('rule luoke_pack_test { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }\n')
        r = subprocess.run(away + [os.path.join(helpers, "yara"), "--no-warnings", rules, sample], capture_output=True, text=True, timeout=60)
        if "luoke_pack_test" not in r.stdout:
            bad.append(f"包里的 YARA 没匹配上测试规则：{(r.stderr or r.stdout).strip()[-200:]}")
        own = os.path.join(t, "eicar.hdb")
        with open(own, "w") as f:
            f.write(f"{hashlib.md5(EICAR).hexdigest()}:{len(EICAR)}:Luoke.Pack.Test\n")
        r = subprocess.run(away + [os.path.join(helpers, "clamscan"), f"--database={own}", "--no-summary", "--stdout", sample] + certs,
                           capture_output=True, text=True, env=env, timeout=120)
        if r.returncode != 1 or not re.search(r"Luoke\.Pack\.Test\S* FOUND", r.stdout):
            bad.append(f"包里的 clamscan 离了 Homebrew 用自带的测试库没认出 EICAR（退出码 {r.returncode}）："
                       f"{(r.stderr or r.stdout).strip()[-200:]}")
        if not db and not need_db:
            log("  !! 没有核对包里的 ClamAV 能不能用带的证书读官方病毒库（--without-virus-db）：螺壳出版时的核对要补上")
            return bad
        if not db:
            return bad + ["这台 Mac 上没有病毒库（/opt/homebrew/var/lib/clamav 或 /usr/local/var/lib/clamav）：核对不了包里的"
                          " ClamAV 能不能用带的证书读官方病毒库。先在这台机器上跑一次 freshclam，再核对"]
        data = os.path.join(t, "clamav")
        os.makedirs(data)
        for n in os.listdir(db):
            if n.endswith((".cvd", ".cld", ".cud")):
                subprocess.run(["cp", "-c", "-p", os.path.join(db, n), os.path.join(data, n)], check=True)
        r = subprocess.run(away + [os.path.join(helpers, "clamscan"), f"--database={data}", "--no-summary", "--stdout", sample] + certs,
                           capture_output=True, text=True, env=env, timeout=600)
        if "FOUND" not in r.stdout:
            bad.append(f"包里的 clamscan 离了 Homebrew 没认出 EICAR（退出码 {r.returncode}）：{(r.stderr or r.stdout).strip()[-200:]}")
        first = sorted(os.listdir(data))[0]
        r = subprocess.run(away + [os.path.join(helpers, "sigtool"), f"--info={os.path.join(data, first)}"] + certs,
                           capture_output=True, text=True, env=env, timeout=120)
        if r.returncode != 0 or "Version:" not in r.stdout:
            bad.append(f"包里的 sigtool 离了 Homebrew 读不了 {first}：{(r.stderr or r.stdout).strip()[-200:]}")
    return bad


def tarball(top: str, out: str) -> str:
    """What the scan's release carries (for the record; luoke-core builds from the tag itself):
    luoke-scan-<version>-macos-arm64.tar.gz with luoke-scan/ at its top, and its SHA-256 in a .sha256 next to it."""
    with open(os.path.join(top, RES, "luoke-accessory.json"), encoding="utf-8") as f:
        version = json.load(f)["version"]
    name = f"luoke-scan-{version}-macos-arm64.tar.gz"
    path = os.path.join(out, name)
    run(["tar", "--no-mac-metadata", "-czf", path, "-C", os.path.dirname(top), os.path.basename(top)],
        env={**os.environ, "COPYFILE_DISABLE": "1"})
    with open(path + ".sha256", "w") as f:
        f.write(f"{sha256(path)}  {name}\n")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.environ.get("LUOKE_OUT", os.path.join(ROOT, "build.noindex")))
    ap.add_argument("--tools-from", default=os.environ.get("LUOKE_SCAN_TOOLS", "/opt/homebrew"), help="装着 clamav、yara 的 Homebrew 前缀")
    ap.add_argument("--verify", metavar="FOLDER", help="只核对一个打好的 luoke-scan 文件夹")
    ap.add_argument("--verify-app", metavar="APP", help="核对螺壳.app 里扫描的那些（正式签名以后也跑）")
    ap.add_argument("--tarball", action="store_true", help="再打成发行用的 tar.gz（和 .sha256）")
    ap.add_argument("--without-virus-db", action="store_true",
                    help="这台机器没有病毒库也照样核对（不核官方病毒库那一项，并在输出里写明）；只给不下载病毒库的 GitHub 发行用")
    a = ap.parse_args()
    need_db = not a.without_virus_db
    if a.verify:
        bad = verify(os.path.abspath(a.verify), need_db=need_db)
    elif a.verify_app:
        app = os.path.abspath(a.verify_app)
        bad = verify(os.path.join(app, "Contents"), in_app=True, need_db=need_db) if app.endswith(".app") else [f"{app} 不是 .app"]
        log(f"== {app}")
    else:
        bin_dir, certs = build(a.tools_from)
        os.makedirs(a.out, exist_ok=True)
        top = assemble(bin_dir, os.path.abspath(a.out), a.tools_from, certs)
        relink(top)
        sign(top)
        bad = verify(top, need_db=need_db)
        log(f"== {top}")
        if a.tarball and not bad:
            log("== " + tarball(top, os.path.abspath(a.out)))
    for b in bad:
        log("  !! " + b)
    log("核对通过" if not bad else f"核对没过：{len(bad)} 处")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
