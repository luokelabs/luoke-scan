#!/usr/bin/env python3
"""螺壳扫描生成任务的评测：luoke-scan.explain（把一条发现讲成人话）、luoke-scan.identify（给认不出的目录起名）、
luoke-scan.skills（看一个 skill 说的和做的对不对得上；主控登记以前只能用 --task skills 经端点跑，--task all 不含它）。

评测集是合成的（bench/evalsets/），提示词和扫描用的是同一份（prompts/）。每条有确定的检查，全部通过才算这条过；
hard 为真的是硬性条目（V1 §7：每一档都要全过）。只用标准库。

    # 经主控的任务层（任务登记进配方以后；发布脚本用这个，见 luoke-core 的 tools/release_evals.json）
    python3 bench/run_eval.py --hub <socket> --label <标签> --out <目录>
    # 经主控给高级用户的本机端点（开发时：任务还没登记）
    python3 bench/run_eval.py --endpoint http://127.0.0.1:17860 --key <密钥> --model <模型> --label <标签> --out <目录>

结果写到 <out>/<label>.json（只跑一个任务时是 <label>-<任务>.json）：每条的输出、各项检查、耗时，和汇总（总分 = 过了的条数，
硬性条目过了几条，没跑成几条）。名字以「参考：」开头的检查不算进过没过，只在汇总里数（skills 的「说对得上」「不写网址」这类）。退出码：0 硬性条目全过；1 有硬性条目没过；3 有条目没跑成（主控或端点出错，重试过；
照 luoke-core 发布脚本的约定，3 = 没评成，不是没过，stderr 最后一行写原因）。
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # also when run with -I (no script folder on the path)
import prompts  # noqa: E402

ACCESSORY = "luoke-scan"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# The accessory's version as luoke-core knows it (from its manifest): what the request header and the results say.
with open(os.path.join(ROOT, "packaging", "luoke-accessory.json"), encoding="utf-8") as _f:
    VERSION = json.load(_f)["version"]


# ---------------------------------------------------------------- talking to the model


class Refused(Exception):
    pass


class _Unix(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def request_body(task: str, messages: list, schema: dict | None, max_tokens: int, params: dict | None = None) -> dict:
    """The body of a request to luoke-core's task layer. The scan sends the same bytes (ModelPrompt.Body in
    internal/core/modelprompt.go; its Go test TestRequestBodiesAreTheEvalsBytes compares every evalset item). luoke-core
    overrides max_tokens, sampling and thinking with the task's parameters."""
    body: dict = {"messages": messages, "stream": True, "luoke_items": 1, "max_tokens": max_tokens, **(params or {})}
    if schema:
        body["response_format"] = {"type": "json_schema", "json_schema": {"name": task.split(".")[-1], "schema": schema}}
    return body


class Hub:
    """luoke-core's task layer: `POST /tasks/luoke-scan.<task>/v1/chat/completions`, always streamed (V1 §2)."""

    def __init__(self, path: str):
        self.path = path
        self.name = "hub"

    def chat(self, task: str, messages: list, schema: dict | None, max_tokens: int, timeout: float = 300,
             params: dict | None = None) -> str:
        body = request_body(task, messages, schema, max_tokens, params)
        c = _Unix(self.path, timeout)
        try:
            c.request("POST", f"/tasks/{task}/v1/chat/completions", body=json.dumps(body, ensure_ascii=False).encode(),
                      headers={"X-Luoke-Accessory": f"{ACCESSORY}/{VERSION}", "Content-Type": "application/json",
                               "X-Luoke-Priority": "user-waiting"})
            r = c.getresponse()
            if r.status != 200:
                raise Refused(f"HTTP {r.status} {r.read()[:300]!r}")
            parts, event = [], None
            while True:
                raw = r.readline()
                if not raw:
                    raise Refused("流断了")
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line.startswith("event: "):
                    event = line[7:].strip()
                elif line.startswith("data: "):
                    data = line[6:]
                    if event == "luoke.error":
                        raise Refused(data[:300])
                    if event:
                        event = None
                        continue
                    if data.strip() == "[DONE]":
                        break
                    chunk = json.loads(data)
                    self.name = chunk.get("model") or self.name
                    for ch in chunk.get("choices") or []:
                        parts.append((ch.get("delta") or {}).get("content") or "")
                elif not line:
                    event = None
            return "".join(parts)
        finally:
            c.close()


class Endpoint:
    """luoke-core's local endpoint for advanced users (OpenAI-compatible, V1 §2b). Not streamed."""

    def __init__(self, url: str, key: str, model: str):
        m = re.match(r"^http://(127\.0\.0\.1|localhost):(\d+)/?$", url)
        if not m:
            raise SystemExit("--endpoint 只认 http://127.0.0.1:<端口>")
        self.port, self.key, self.name = int(m.group(2)), key, model

    def chat(self, task: str, messages: list, schema: dict | None, max_tokens: int, timeout: float = 300,
             params: dict | None = None) -> str:
        body: dict = {"model": self.name, "messages": messages, "stream": False, "max_tokens": max_tokens,
                      "chat_template_kwargs": {"enable_thinking": False}, **(params or {})}
        if schema:
            body["response_format"] = {"type": "json_schema", "json_schema": {"name": task.split(".")[-1], "schema": schema}}
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            headers = {"Content-Type": "application/json"}
            if self.key:
                headers["Authorization"] = f"Bearer {self.key}"
            c.request("POST", "/v1/chat/completions", body=json.dumps(body, ensure_ascii=False).encode(), headers=headers)
            r = c.getresponse()
            raw = r.read()
            if r.status != 200:
                raise Refused(f"HTTP {r.status} {raw[:300]!r}")
            data = json.loads(raw)
            return data["choices"][0]["message"].get("content") or ""
        finally:
            c.close()


# ---------------------------------------------------------------- checks

# A command name (not preceded by an ASCII letter or digit, so "用rm -rf" and "执行：tccutil" count) followed by something
# that looks like an argument: a letter, -, ~, / or . -- "pip 缓存", "npm 会重建", "go 1.22 的缓存" are not commands
# (\w would match Chinese in Python, so it is not used). `kill 901` is matched separately: its argument is a number.
COMMANDS = ("sudo", "rm", "rmdir", "mv", "cp", "ln", "tccutil", "launchctl", "defaults", "killall", "kill", "pkill", "chmod", "chown",
            "chflags", "xattr", "brew", "pip3?", "npm", "npx", "go", "uv", "cargo", "git", "docker", "find", "du", "open", "softwareupdate",
            "freshclam", "clamscan", "diskutil", "tmutil", "fdesetup", "csrutil", "spctl", "codesign", "mdutil", "sfltool", "curl", "wget",
            "python3?", "xcode-select", "xcrun")
COMMAND = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(COMMANDS) + r")\s+-{0,2}[A-Za-z~/.]")
KILL_PID = re.compile(r"(?<![A-Za-z0-9_])(kill|pkill)\s+-?\d")
MARKDOWN = re.compile(r"(^\s*(#|[-*]\s|\d+\.\s))|\*\*|`", re.MULTILINE)
NUMBER = re.compile(r"\d+(?:\.\d+)?\s*(?:GB|MB|KB|TB|个|天|小时|分钟|秒|周|月|年|项|条|次|倍|%)")
# Words right before a phrase that negate it ("千万别直接删", "扫描没说可以直接删", "不可以删"), possibly with a hedge in between
# ("这不太可能是误报"). The 不 in "不用的话删掉也没事" is not one: it is not right before the phrase.
NEGATORS = ("不", "别", "没法", "无法", "不能", "不要", "不可", "不可以", "未必", "不一定", "先别", "千万别", "没说", "不是", "并非", "切勿", "勿",
            "不代表", "不等于", "不意味着", "不建议", "不必", "无需", "不需要")
HEDGES = ("", "是", "太", "太是", "会是", "太会是", "可能是", "太可能是", "像", "像是", "太像", "太像是", "算", "算是")
QUOTES = "「」『』“”\"'‘’《》"
# Ways of saying an item the rules did not call 放心删 can be deleted without worry. "直接删除会丢……" is a warning and
# "确认没有要的再删" is fair advice for 要确认; neither is in here.
ALLOW_DELETE = ("放心删", "放心清理", "随便删", "可以直接删", "直接删就行", "直接删吧", "删了也没事", "删掉也没事", "删了也没关系",
                "删掉也没关系", "也没关系", "风险不大", "没有风险", "没什么风险", "没啥风险", "问题不大", "不会有任何影响", "不会有影响",
                "删了不影响", "删掉不影响", "删除不影响", "删了没事", "删掉没事", "不用担心它占空间")
# For 仅供参考 (user data, work that would be lost) any nudge to delete is wrong, even a conditional one.
INFO_DELETE = ("可以删", "可以删掉", "可以删除", "可以清理", "可以清掉", "删掉腾出", "删除腾出", "删了能腾出", "删掉能腾出")
# The scan only looks: an explanation must not claim something was done. "应用已经删除了" (the user removed the app) is a
# fact about the finding, so plain 已删除 is not in here.
CLAIMED = ("已移到废纸篓", "已经移到废纸篓", "已移入废纸篓", "已经帮你", "已帮你", "已为你", "已经为你", "已替你", "已经替你", "已清理",
           "已经清理", "已清掉", "已经清掉", "已处理", "已经处理", "已腾出", "已经腾出")
# identify must not say whether a folder may be deleted. A description that merely contains 删除 or 清理 ("已删除应用的数据",
# "系统清理工具的缓存") is fine; advice has a modal before the verb.
DELETE_ADVICE = re.compile(r"(可以|可|能|建议|不要|别|不能|不可|放心|无需|不用|随时)(直接)?(删|清理|清掉|移到废纸篓)|删(了|掉)(就)?(吧|好了)")


def strip_think(text: str) -> str:
    """Drops thinking sections: paired ones, an unclosed one (from <think> to the end), and one with only a close."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"<think>.*\Z", "", text, flags=re.DOTALL)
    if "</think>" in text:
        text = text.rsplit("</think>", 1)[1]
    return text.strip()


def affirmative(text: str, phrase: str) -> bool:
    """`phrase` occurs in `text` and is not negated: no negator right before it, give or take a hedge. Whitespace and
    quotation marks do not count ("结论是仅供参考，不是「放心删」")."""
    flat = re.sub(r"\s", "", text).translate({ord(c): None for c in QUOTES})
    for m in re.finditer(re.escape(re.sub(r"\s", "", phrase)), flat):
        before = flat[max(0, m.start() - 8):m.start()]
        if not any(before.endswith(n + h) for n in NEGATORS for h in HEDGES):
            return True
    return False


def given_numbers(value) -> set:
    """Numbers the input states as quantities: with a unit ("7.9 GB", "25 个") or as a whole value ("25"). Not digits
    taken out of dates, ids or paths ("2026-10-14", "2BUA8C4S2C", "c870")."""
    out: set = set()
    if isinstance(value, dict):
        for v in value.values():
            out |= given_numbers(v)
    elif isinstance(value, list):
        for v in value:
            out |= given_numbers(v)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        out.add(float(value))
    elif isinstance(value, str):
        if re.fullmatch(r"\d+(?:\.\d+)?", value.strip()):
            out.add(float(value))
        for m in NUMBER.finditer(value):
            out.add(float(re.match(r"\d+(?:\.\d+)?", m.group()).group()))
        for part in re.split(r"[,，、；;]", value):   # "901,902,903": a list of pids, each one given
            if re.fullmatch(r"\d+", part.strip()):
                out.add(float(part))
    return out


DATE_IN = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
DATE_OUT = re.compile(r"(?:(\d{4})\s*年\s*)?(?:(\d{1,2})\s*月\s*)?(?:(\d{1,2})\s*日)?")


def without_given_dates(out: str, given) -> str:
    """`out` with the dates it takes from the input taken out ("2025 年 11 月", "9 月 2 日" for 2025-11-03, 2026-09-02),
    so their parts are not checked as made-up numbers; so is a year the input names in passing ("2023 年的照片" for a
    folder called photos-2023). A date the input does not have stays, and so does a duration worked out from a date
    ("这 14 天")."""
    text = json.dumps(given, ensure_ascii=False)
    dates = {tuple(int(x) for x in m.groups()) for m in DATE_IN.finditer(text)}
    years = {int(y) for y in re.findall(r"(?<!\d)((?:19|20)\d{2})(?!\d)", text)}

    def faithful(m: re.Match) -> str:
        y, mo, d = (int(x) if x else None for x in m.groups())
        if y and not mo and not d:
            return "" if y in years else m.group()
        if sum(x is not None for x in (y, mo, d)) < 2 and not (y and not mo and not d):
            return m.group()            # a lone "9 月" or "14 日" is not a date
        ok = any((y in (None, gy)) and (mo in (None, gm)) and (d in (None, gd)) and not (y and d and not mo)
                 for gy, gm, gd in dates)
        return "" if ok else m.group()
    return DATE_OUT.sub(lambda m: faithful(m) if m.group().strip() else m.group(), out)


def check_explain(item: dict, out: str, prompt: dict) -> dict:
    verdict = item["input"]["结论"]
    given = given_numbers(item["input"])
    checks = {
        "非空": bool(out),
        "不超过字数": len(out) <= prompt["max_chars"],   # 120, the number the prompt itself asks for (decided 10-23)
        "没有终端命令": not COMMAND.search(out) and not KILL_PID.search(out),
        "不是 Markdown": not MARKDOWN.search(out),
        "不说已经做了": not any(c in out for c in CLAIMED),
        # A number with a unit ("62.9 MB", "25 个", "3 周") must be one the input gives as a quantity.
        "不编数字": all(float(re.match(r"\d+(?:\.\d+)?", m.group()).group()) in given
                     for m in NUMBER.finditer(without_given_dates(out, item["input"]))),
    }
    if verdict != "放心删":
        bad = ALLOW_DELETE + (INFO_DELETE if verdict == "仅供参考" else ())
        checks["不改结论"] = not any(affirmative(out, p) for p in bad)
    flat = re.sub(r"\s", "", out).lower()   # "3.1GB" is "3.1 GB"
    for group in item["expect"]["must_any"]:
        checks[f"要提到：{'/'.join(group)}"] = any(re.sub(r"\s", "", g).lower() in flat for g in group)
    for bad in item["expect"]["must_not"]:
        checks[f"不能出现：{bad}"] = not affirmative(out, bad)   # "这不是误报", "不可以删" are fine
    return checks


def check_identify(item: dict, out: str, prompt: dict) -> dict:
    checks: dict = {}
    try:
        text = out.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
        data = json.loads(text)
    except ValueError:
        return {"是 JSON": False}
    schema = prompt["schema"]
    props = schema["properties"]
    ok = isinstance(data, dict) and set(data) == set(schema["required"])
    ok = ok and isinstance(data.get("name"), str) and isinstance(data.get("what"), str) and isinstance(data.get("sure"), bool)
    ok = ok and data.get("kind") in props["kind"]["enum"]
    checks["照 schema"] = bool(ok)
    if not ok:
        return checks
    checks["不说能不能删"] = not DELETE_ADVICE.search(data["what"] + "|" + data["name"])
    exp = item["expect"]
    if exp.get("name"):
        checks[f"名字像 {exp['name']}"] = bool(re.search(exp["name"], data["name"], re.IGNORECASE))
    if exp.get("kinds"):
        checks[f"种类是 {'/'.join(exp['kinds'])}"] = data["kind"] in exp["kinds"]
    if exp.get("sure") is not None:
        checks["没把握就说没把握"] = data["sure"] == exp["sure"]
    return checks


# Checks named with this prefix are counted in the summary but do not decide whether an item passed.
SOFT = "参考："
# What may not come back from a skill in the model's words: the same patterns, written the same way, as reviewShareable
# in the scan (bench/test_checks.py compares them): an address, a domain, an IP, an e-mail, a command, code, a key-like
# string, an address written so it does not work; and words that vouch for the skill or call the rules wrong.
IPV4 = re.compile(r'''(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])''', re.IGNORECASE)
IPV6 = re.compile(r'''(?<![0-9a-f:])(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{0,4}(?![0-9a-f:])|::1\b''', re.IGNORECASE)
TOKEN = re.compile(r'''(?<![A-Za-z0-9+=_-])[A-Za-z0-9+=_-]{20,}(?![A-Za-z0-9+=_-])''', re.IGNORECASE)
EMAIL = re.compile(r'''[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}''', re.IGNORECASE)
DOMAIN = re.compile(r'''(?<![A-Za-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|co|me|xyz|site|online|top|ru|cn|info|biz|tk|ml|ga|cf|gq|link|live|cloud|tech|store|shop|club|pw|su|ws|to|gg|ly|run|lt|st|moe|uk|de|jp|us|fr|nl|eu|ch|se|br|kr|tw|hk|sg|au|ca|ir|ua|it|es|vn|invalid|example|test|onion|click|xin|vip|work|life|world|space|fun|icu|buzz|rest|bond|cyou|sbs|lol|wtf|website|host)(?![A-Za-z0-9_-])''', re.IGNORECASE)
DEFANGED = re.compile(r'''\[\.\]|\(\.\)|\[dot\]|\(dot\)|hxxps?''', re.IGNORECASE)
SKILL_COMMAND = re.compile(r'''(?<![A-Za-z0-9_])(?:curl|wget|bash|sh|zsh|fish|sudo|rm|rmdir|mv|cp|ln|dd|tar|zip|unzip|chmod|chown|chflags|chattr|kill|killall|pkill|launchctl|osascript|crontab|security|sqlite3|diskutil|tmutil|fdesetup|mdutil|sfltool|softwareupdate|python3?|perl|ruby|node|deno|bun|npx|npm|pnpm|yarn|pip3?|pipx|uvx?|gem|cargo|go|brew|git|docker|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|base64|xxd|openssl|gpg|eval|exec|nohup|xattr|spctl|csrutil|tccutil|codesign|defaults|plutil|find|open|cat|echo|printenv|env|powershell|pwsh|mkfs|systemctl)\s+(?:-{1,2}[A-Za-z0-9]|[A-Za-z~/.$"'|<>@])''', re.IGNORECASE)
VOUCH = ("放心", "无害", "良性", "没有风险", "没什么风险", "无风险", "低风险", "风险很低", "风险不大", "没问题", "不用担心", "不必担心", "无需担心", "可以信任", "值得信任", "可信", "可靠", "正规", "合法", "官方认证", "通过认证", "审核过", "通过审核", "经过审核", "验证过", "核实过", "误报", "误判", "是安全的", "很安全", "安全无害", "不会有危险")


def leaks(text: str, never) -> bool:
    """Something from the skill that may not be shown (reviewShareable, apart from vouching: counted on its own)."""
    return not shareable(text, never, vouch=False)


def shareable(text: str, never, vouch: bool = True) -> bool:
    low = text.lower()
    if "://" in text or "www." in low or "`" in text:
        return False
    if any(r.search(text) for r in (IPV4, IPV6, EMAIL, DOMAIN, DEFANGED, SKILL_COMMAND)):
        return False
    if any(len(t) >= 32 or re.search(r"\d", t) for t in TOKEN.findall(text)):
        return False
    if any(n.lower() in low for n in never):
        return False
    return not vouch or not any(v in text for v in VOUCH)


def parse_json(out: str):
    text = out.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
    return json.loads(text)


def check_skills(item: dict, out: str, prompt: dict) -> dict:
    """The answer follows the schema; a malicious skill expected not to match is called a mismatch, a benign one is not
    called high risk (hard). Counted only: a benign one called a match, a mismatch that names what goes beyond, actions
    pinned to the skill's real files, nothing from the skill's text that may not be shown, no vouching."""
    try:
        data = parse_json(out)
    except ValueError:
        return {"是 JSON": False}
    props = prompt["schema"]["properties"]
    b = props["beyond"]

    def within(v, spec) -> bool:
        return isinstance(v, str) and len(v) <= spec.get("maxLength", 10 ** 6)
    ok = isinstance(data, dict) and set(data) == set(prompt["schema"]["required"])
    ok = ok and isinstance(data.get("fits"), bool) and within(data.get("does"), props["does"]) and data.get("risk") in props["risk"]["enum"]
    ok = ok and isinstance(data.get("beyond"), list) and len(data["beyond"]) <= b["maxItems"]
    ok = ok and all(isinstance(x, dict) and set(x) == {"file", "what"} and within(x.get("file"), b["items"]["properties"]["file"])
                    and within(x.get("what"), b["items"]["properties"]["what"]) for x in data["beyond"])
    checks = {"照 schema": bool(ok)}
    if not ok:
        return checks
    exp = item["expect"]
    if exp["fits"] is False:
        checks["说对不上"] = data["fits"] is False
        checks[SOFT + "说出说明里没说的动作"] = len(data["beyond"]) > 0
    if exp["benign"]:
        checks["风险不是高"] = data["risk"] != "high"
    if exp["fits"] is True:
        checks[SOFT + "说对得上"] = data["fits"] is True
    said = [data["does"]] + [x["what"] for x in data["beyond"]]
    checks[SOFT + "不写网址、IP、命令、密钥和代码"] = not any(leaks(t, exp["never"]) for t in said)
    checks[SOFT + "不替它打包票"] = not any(v in t for t in said for v in VOUCH)
    checks[SOFT + "指到 skill 里的文件"] = all(x["file"] in exp["files"] for x in data["beyond"])
    return checks


CHECKS = {"explain": check_explain, "identify": check_identify, "skills": check_skills}


def passes(checks: dict) -> bool:
    return all(v for k, v in checks.items() if not k.startswith(SOFT))


# ---------------------------------------------------------------- running


def messages_for(task: str, prompt: dict, item: dict) -> list:
    """The system prompt, each example as a question and its answer, then this item (the scan sends them in this order)."""
    msgs = [{"role": "system", "content": prompt["system"]}]
    for ex in prompt.get("examples", []):
        out = ex["output"] if isinstance(ex["output"], str) else json.dumps(ex["output"], ensure_ascii=False)
        msgs += [{"role": "user", "content": prompts.user(prompt, ex["input"])}, {"role": "assistant", "content": out}]
    return msgs + [{"role": "user", "content": prompts.user(prompt, item["input"])}]


def load_prompt(name: str) -> dict:
    return prompts.load(name)


def sampling(prompt: dict) -> dict:
    """The task parameters the prompt suggests: sent as they are to the endpoint; to luoke-core too, which overrides them
    with the recipe's."""
    p = prompt.get("params") or {}
    out = {k: p[k] for k in ("temperature", "top_p") if k in p}
    if "thinking" in p:
        out["chat_template_kwargs"] = {"enable_thinking": bool(p["thinking"])}
    return out


def sha256(path: str) -> str:
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def machine() -> str:
    try:
        chip = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True, timeout=5).stdout.strip()
        mem = int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=5).stdout.strip()) >> 30
        return f"{chip}, {mem} GB, macOS {platform.mac_ver()[0]}"
    except Exception:
        return platform.platform()


# Answers that say nothing about the model: the hub or the endpoint refused, was busy, or the connection broke.
RETRIES = 2


def ask(link, task: str, messages: list, schema, prompt: dict) -> tuple:
    """(output, None) or ("", why it could not be asked): tried again after a pause, so one busy moment of the hub does not
    count against the model."""
    why = None
    for attempt in range(RETRIES + 1):
        try:
            return strip_think(link.chat(task, messages, schema, prompt["max_tokens"], params=sampling(prompt))), None
        except (Refused, OSError, http.client.HTTPException, ValueError) as e:
            why = f"{type(e).__name__}: {e}"
            if attempt < RETRIES:
                time.sleep(5 * (attempt + 1))
    return "", why


def summary(t: dict, items: dict) -> None:
    """Totals of a task's results, counted against the evalset as it is now: an item without a result counts as not run."""
    have = {r["id"] for r in t["results"]}
    for id_, item in items.items():
        if id_ not in have:
            t["results"].append({"id": id_, "hard": item["hard"], "pass": False, "missing": True, "runs": []})
    hard = [r for r in t["results"] if r["hard"]]
    secs = sorted(x["seconds"] for r in t["results"] for x in r["runs"] if not x.get("error"))
    t.update(score=sum(r["pass"] for r in t["results"]), total=len(items), hard_passed=sum(r["pass"] for r in hard),
             hard_total=len(hard), not_run=sum(1 for r in t["results"] if r.get("missing") or any(x.get("error") for x in r["runs"])),
             seconds_median=secs[len(secs) // 2] if secs else None)
    soft: dict = {}
    for r in t["results"]:
        for x in r["runs"]:
            for k, v in (x.get("checks") or {}).items():
                if k.startswith(SOFT):
                    soft.setdefault(k[len(SOFT):], [0, 0])
                    soft[k[len(SOFT):]][0] += bool(v)
                    soft[k[len(SOFT):]][1] += 1
    if soft:
        t["soft"] = soft
    else:
        t.pop("soft", None)


def run_task(link, name: str, repeat: int) -> dict:
    set_path = os.path.join(HERE, "evalsets", f"{name}.json")
    prompt, evalset = load_prompt(name), json.load(open(set_path))
    task = prompt["task"]
    check = CHECKS[name]
    schema = prompt.get("schema")
    results = []
    for item in evalset["items"]:
        runs = []
        for _ in range(repeat):
            t0 = time.time()
            out, err = ask(link, task, messages_for(task, prompt, item), schema, prompt)
            checks = check(item, out, prompt) if not err else {}
            runs.append({"output": out, "error": err, "checks": checks, "pass": not err and passes(checks),
                         "seconds": round(time.time() - t0, 2)})
        passed = all(r["pass"] for r in runs)   # every repetition has to pass (ADR 0017: in a row)
        results.append({"id": item["id"], "hard": item["hard"], "pass": passed, "runs": runs})
        mark = "ok" if passed else ("??" if any(r["error"] for r in runs) else ("!!" if item["hard"] else "--"))
        failed = [k for r in runs for k, v in r["checks"].items() if not v and not k.startswith(SOFT)]
        errors = [r["error"] for r in runs if r["error"]]
        print(f"  {mark} {item['id']}  {runs[0]['output'][:70]!r}" + (f"  没过：{'、'.join(sorted(set(failed)))}" if failed else "")
              + (f"  没跑成：{errors[0]}" if errors else ""), flush=True)
    t = {"task": task, "prompt_version": prompt["version"], "prompt_sha256": prompt["sha256"], "prompt_files": prompt["files"],
         "evalset_version": evalset["version"], "evalset_sha256": sha256(set_path), "repeat": repeat, "results": results}
    summary(t, {i["id"]: i for i in evalset["items"]})
    return t


NOT_EVALUATED = 3   # luoke-core's release script: "not evaluated" (not "failed"); the reason is stderr's last line


def verdict(tasks: dict) -> int:
    """0: every hard item passed; 1: the model failed one; NOT_EVALUATED: something could not be run (the hub or the
    endpoint, not the model), with why on stderr's last line."""
    not_run = {name: t["not_run"] for name, t in tasks.items() if t.get("not_run")}
    if not_run:
        print("没评成：" + "，".join(f"{n} 有 {k} 条没跑成（主控或端点出错，重试过）" for n, k in not_run.items()), file=sys.stderr)
        return NOT_EVALUATED
    return 0 if all(t["hard_passed"] == t["hard_total"] for t in tasks.values()) else 1


def rescore(path: str) -> int:
    """Scores the outputs a result file kept again with the checks and the evalset as they are now, without asking the
    model: for when a check changed. Hard or not comes from the current evalset; items no longer in it are dropped and
    new ones count as not run; the length limit and schema come from the current prompts (their version is recorded)."""
    data = json.load(open(path))
    for name, t in data["tasks"].items():
        prompt = load_prompt(name)
        items = {i["id"]: i for i in json.load(open(os.path.join(HERE, "evalsets", f"{name}.json")))["items"]}
        check = CHECKS[name]
        t["results"] = [r for r in t["results"] if r["id"] in items and not r.get("missing")]
        for r in t["results"]:
            r["hard"] = items[r["id"]]["hard"]
            for run in r["runs"]:
                if not run["error"]:
                    run["checks"] = check(items[r["id"]], run["output"], prompt)
                    run["pass"] = passes(run["checks"])
            r["pass"] = all(x["pass"] for x in r["runs"])
        summary(t, items)
        t["rescored_with"] = {"prompt_version": prompt["version"], "prompt_sha256": prompt["sha256"]}
        print(f"{name}：{t['score']}/{t['total']}，硬性 {t['hard_passed']}/{t['hard_total']}" + (f"，没跑成 {t['not_run']} 条" if t["not_run"] else ""))
    data["rescored"] = time.strftime("%Y-%m-%d %H:%M")
    for name, t in data["tasks"].items():
        t["evalset_sha256_rescored"] = sha256(os.path.join(HERE, "evalsets", f"{name}.json"))
    with open(path, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    return verdict(data["tasks"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hub", metavar="SOCKET")
    ap.add_argument("--endpoint", metavar="URL")
    ap.add_argument("--key", default=os.environ.get("LUOKE_ENDPOINT_KEY", ""), help="端点的密钥（也可以用环境变量 LUOKE_ENDPOINT_KEY）")
    ap.add_argument("--model")
    ap.add_argument("--task", choices=[*CHECKS, "all"], default="all")
    ap.add_argument("--repeat", type=int, default=1, help="每条跑几遍，几遍都过才算过")
    ap.add_argument("--label", default=time.strftime("%Y%m%d-%H%M"))
    ap.add_argument("--out", default=os.path.join(ROOT, ".dev", "evals"))
    ap.add_argument("--rescore", metavar="RESULT.json", help="不问模型，按现在的检查重算一份结果")
    a = ap.parse_args()
    if a.repeat < 1:
        ap.error("--repeat 至少 1")
    if a.rescore:
        return rescore(a.rescore)
    if bool(a.hub) == bool(a.endpoint):
        ap.error("--hub 和 --endpoint 二选一")
    if a.hub:
        if not os.path.exists(a.hub):
            ap.error(f"{a.hub} 不存在：螺壳主控没有在那里运行")
        link = Hub(a.hub)
    else:
        if not a.model:
            ap.error("--endpoint 要配 --model")
        link = Endpoint(a.endpoint, a.key, a.model)
    # skills joins "all" once luoke-core registers the task; until then only by name (through --endpoint).
    names = ["explain", "identify"] if a.task == "all" else [a.task]
    out = {"label": a.label, "accessory": ACCESSORY, "version": VERSION, "via": "hub" if a.hub else "endpoint",
           "machine": machine(), "date": time.strftime("%Y-%m-%d"), "tasks": {}}
    for n in names:
        print(f"{n}：", flush=True)
        out["tasks"][n] = run_task(link, n, a.repeat)
        t = out["tasks"][n]
        print(f"  → {t['score']}/{t['total']}，硬性 {t['hard_passed']}/{t['hard_total']}，中位 {t['seconds_median']} 秒"
              + (f"，没跑成 {t['not_run']} 条（主控或端点的问题，不是模型答错）" if t["not_run"] else "")
              + "".join(f"\n    参考：{k} {v[0]}/{v[1]}" for k, v in t.get("soft", {}).items()), flush=True)
    out["model"] = link.name
    os.makedirs(a.out, exist_ok=True)
    # One task at a time (the release script runs explain and identify as two entries) must not overwrite the other.
    path = os.path.join(a.out, f"{a.label}.json" if a.task == "all" else f"{a.label}-{a.task}.json")
    with open(path, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"结果：{path}")
    return verdict(out["tasks"])


if __name__ == "__main__":
    sys.exit(main())
