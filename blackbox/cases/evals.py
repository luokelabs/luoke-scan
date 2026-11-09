"""三套评测（清理、skill、给 AI 看的说明文件）：汇总的分数和逐条的结果（--json）；skill 语义检查的评测集和提示词示范
由用例生成，要和仓库里的一样。"""
from __future__ import annotations

import os

from harness import Run, case

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(HERE)


def repo(rel: str) -> str:
    return os.path.join(ROOT, rel)


for _name, _cases in (("cleanup", "evals/cleanup/cases.json"), ("skills", "evals/skills/cases.json"),
                      ("agentfiles", "evals/agentfiles/cases.json")):
    def _run(r: Run, name: str = _name, cases: str = _cases) -> None:
        r.cli(f"eval-{name}", "--cases", repo(cases))
        r.cli(f"eval-{name}", "--cases", repo(cases), "--json", json_out=True)
    case(f"evals/{_name}", f"eval-{_name}：汇总的分数和每条用例的结果")(_run)


@case("evals/make-skill-evalset", "用 skill 的用例生成语义检查的评测集和提示词示范：和仓库里的 bench/evalsets/skills.json、prompts/skills.examples.json 一字不差")
def make_skill_evalset(r: Run) -> None:
    evalset, shown = os.path.join(r.fx.root, "skills.json"), os.path.join(r.fx.root, "skills.examples.json")
    r.cli("make-skill-evalset", "--cases", repo("evals/skills/cases.json"), "--examples", repo("evals/skills/examples.json"),
          "--evalset", evalset, "--prompt-examples", shown)
    same = {rel: open(path, encoding="utf-8").read() == open(repo(rel), encoding="utf-8").read()
            for rel, path in (("bench/evalsets/skills.json", evalset), ("prompts/skills.examples.json", shown))}
    r.note("和仓库里的一样：" + "、".join(f"{k} {'是' if v else '否'}" for k, v in same.items()))
