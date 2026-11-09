# 给 AI 看的说明文件检查的评测

`cases.json`：合成的 AGENTS.md、CLAUDE.md、Cursor 规则、Copilot 说明，13 个恶意、13 个正常。格式和 `evals/skills/cases.json` 一样（`SkillEvalCase`），只是文件写进一个假项目（`~/Projects/<用例编号>/`）；`place: "home"` 的写进假家目录。

```bash
.build/go/luoke-scan eval-agentfiles
```

过线：恶意的全报，并且至少到 `min`、认出 `kind`；正常的一个都不报成高，也不超过 `max`（默认低）。

加用例时：恶意的用 `example.invalid` 这类不存在的地址；正常的照真实项目里常见的写法（构建命令、目录、代码风格、怎么维护说明文件自己），越像真的越好，误报就是从这些写法里来的。
