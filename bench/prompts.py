"""Reads a task's prompt files from prompts/ (top-level ADR 0019): <task>.task.json (name, version, limits, suggested
parameters), <task>.system.txt, <task>.user.txt, <task>.examples.json, and <task>.schema.json for a task whose output
is JSON. Placeholders are {{name}}; one that is not filled, or a value given for a placeholder the file does not have,
is an error when loading, not a prompt with a hole in it. Only the standard library.

    import prompts
    p = prompts.load("explain")
    p["system"], p["examples"], p["schema"], p["max_tokens"], prompts.user(p, {...}), p["sha256"]
"""
from __future__ import annotations

import hashlib
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
DIR = os.path.join(os.path.dirname(HERE), "prompts")
PLACEHOLDER = re.compile(r"\{\{([a-z_]+)\}\}")


class PromptError(Exception):
    pass


def fill(template: str, values: dict, where: str) -> str:
    """The template with each {{name}} replaced; every placeholder filled and every value used, or PromptError."""
    wanted = set(PLACEHOLDER.findall(template))
    if wanted != set(values):
        missing, extra = sorted(wanted - set(values)), sorted(set(values) - wanted)
        raise PromptError(f"{where}：" + "；".join(([f"没填 {missing}"] if missing else []) + ([f"文件里没有 {extra}"] if extra else [])))
    return PLACEHOLDER.sub(lambda m: str(values[m.group(1)]), template)


KINDS = (".task.json", ".system.txt", ".user.txt", ".retry.txt", ".examples.json", ".schema.json")


def files(name: str) -> list[str]:
    """The task's files, sorted: what its fingerprint covers (exactly these names: an editor's backup is not one)."""
    return sorted(f for f in os.listdir(DIR) if f in {name + k for k in KINDS} or f == "_shared.txt")


def read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def raw(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def load(name: str) -> dict:
    """Everything a request for the task needs, the system prompt filled in. `schema` is what goes to the model
    (keys starting with x- taken out); `sha256` fingerprints all of the task's files."""
    base = os.path.join(DIR, name)
    task = json.loads(read(base + ".task.json"))
    schema_path = base + ".schema.json"
    full_schema = json.loads(read(schema_path)) if os.path.exists(schema_path) else None
    values = {}
    if "max_chars" in task:
        values["max_chars"] = task["max_chars"]
    # An enum described in the schema (x-describe) fills {{<property>s}}: identify's kind is {{kinds}}, skills' risk {{risks}}.
    for prop, spec in (full_schema or {}).get("properties", {}).items():
        if "x-describe" in spec:
            described = [k for k, _ in spec["x-describe"]]
            if sorted(described) != sorted(spec.get("enum", [])):
                raise PromptError(f"{name}.schema.json：{prop} 的 x-describe 和 enum 对不上")
            values[prop + "s"] = "\n".join(f"- {k}：{d}" for k, d in spec["x-describe"])
    # Every value the task has must be used: a number written into the text instead would be the second copy this is
    # here to prevent.
    system = fill(read(base + ".system.txt"), values, f"{name}.system.txt")
    if "{{" in system:
        raise PromptError(f"{name}.system.txt：有认不出的占位符（只能是小写字母和下划线）")
    h = hashlib.sha256()
    for f in files(name):
        h.update(f.encode() + b"\0" + raw(os.path.join(DIR, f)) + b"\0")
    return {**task, "system": system, "user_template": read(base + ".user.txt"),
            "examples": json.loads(read(base + ".examples.json")), "schema": strip_x(full_schema), "sha256": h.hexdigest(),
            "files": files(name)}


def user(prompt: dict, data) -> str:
    """One user turn: the task's user.txt with the input (a finding, a folder's metadata) as JSON."""
    return fill(prompt["user_template"], {"input": json.dumps(data, ensure_ascii=False)}, prompt["task"] + " 的 user.txt")


def strip_x(schema, names: bool = False):
    """The schema without this repository's notes (keys starting with x-). `names`: the keys are property names (the
    map under "properties"), kept whatever they are."""
    if isinstance(schema, dict):
        return {k: strip_x(v, names=k == "properties" and not names) for k, v in schema.items() if names or not k.startswith("x-")}
    if isinstance(schema, list):
        return [strip_x(v) for v in schema]
    return schema
