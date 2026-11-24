package core

import (
	"strconv"
	"strings"
)

// AgentFileRule: the instructions AI coding tools read by themselves (agentfiles.go), checked with the skills' text
// checks for words to the agent, running code from the network, and the rest of what a skill's prose is checked for.
// One finding per file with something to say, only for reference: nothing is planned, cleaned or deleted.
type AgentFileRule struct {
	Places []AgentFilePlace
	Limits AgentFileLimits
}

func init() { Register("agentfile", NewAgentFileRule) }

// NewAgentFileRule is the same for this Mac and a fake home: it only reads files.
func NewAgentFileRule(l *Layout, f *Fakes) Rule {
	return &AgentFileRule{Places: AgentFilePlaces, Limits: DefaultAgentFileLimits()}
}

func (r *AgentFileRule) ID() string      { return "agentfile" }
func (r *AgentFileRule) Emits() []string { return []string{"agentfile"} }

// adjustedSignals: what instruction files do as a matter of course, and a skill does not: say how to keep themselves
// and the other agent files up to date, where the project's skills and slash commands live (context only), how the
// project's own agent settings are set up (low).
func adjustedSignals(signals []SkillSignal) []SkillSignal {
	out := make([]SkillSignal, len(signals))
	for i, s := range signals {
		if s.Kind == SignalAgentTamper {
			if strings.HasPrefix(s.Label, "改 AI 的记忆或长期指令") || strings.HasPrefix(s.Label, skillLabelCommands) ||
				strings.HasPrefix(s.Label, "改别的 skill") {
				s.Severity = ""
			} else if s.Severity != "" {
				s.Severity = Low
			}
		}
		out[i] = s
	}
	return out
}

func agentFileHow(top SignalKind) string {
	switch top {
	case SignalInjection:
		return "用文本编辑器打开那个文件看看那几行；不是你写的，AI 就先别在这个项目里用，或者删掉那几行"
	case SignalExfil, SignalDownloadExec, SignalDestructive, SignalPersistence, SignalEscalation:
		return "AI 打开这个项目时会照着这个文件做；不是你写的，先别让 AI 在这个项目里干活，看清楚那几行再说"
	}
	return "用文本编辑器打开那个文件看看那几行；认得、是你自己写的就不用管"
}

// AgentFileFinding is the finding for a file, or nil when nothing it found counts on its own.
func AgentFileFinding(file AgentFile, signals []SkillSignal, also []string) *Finding {
	ordered, severity := orderedSignals(signals)
	if severity == "" {
		return nil
	}
	top := ordered[0]
	concerns := distinctLabels(ordered)
	name := aiClean(file.Name, 60)
	who := file.Agent + " 读的 " + name
	if file.Scope == ScopeProject && file.Project != "" {
		who = "项目 " + aiClean(aiNSLast(file.Project), 40) + " 里 " + who
	}
	title := who + "：" + top.Label
	if concerns > 1 {
		title += "，另有 " + strconv.Itoa(concerns-1) + " 处要看"
	}
	opens := "时"
	if file.Scope == ScopeProject {
		opens = "这个项目"
	}
	ev := map[string]string{"agent": file.Agent, "scope": string(file.Scope), "file": name, "kinds": signalKinds(ordered),
		"why": "AI 写代码的工具打开" + opens + "会自动读这个文件、照着做，用的是你的权限。查到：" + signalSummary(ordered, signals),
		"how": agentFileHow(top.Kind)}
	if len(also) > 0 {
		ev["also"] = skillAlsoText(also)
	}
	// Keyed on the file and its contents: a later change is a new finding, not hidden by a "以后别提" for this one.
	return &Finding{Rule: "agentfile." + string(top.Kind), Category: CatSkill, Severity: severity, Verdict: Info, Path: file.Path,
		Title: title, Evidence: ev, Key: file.RealPath + "|" + file.Digest}
}

func (r *AgentFileRule) Run(ctx *Context) ([]Finding, error) {
	found := FindAgentFiles(ctx, r.Places, r.Limits)
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted)
	}
	// The same file copied into several projects (a template): said once.
	var order []string
	copies := map[string][]AgentFile{}
	for _, f := range found.Files {
		if _, ok := copies[f.Digest]; !ok {
			order = append(order, f.Digest)
		}
		copies[f.Digest] = append(copies[f.Digest], f)
	}
	out := []Finding{}
	for _, d := range order {
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted, out...)
		}
		group := copies[d]
		var also []string
		for _, f := range group[1:] {
			also = append(also, ctx.Shown(f.Path))
		}
		signals := adjustedSignals(SkillSignals(group[0].asSkill()))
		if f := AgentFileFinding(group[0], signals, also); f != nil {
			out = append(out, *f)
		}
	}
	if found.More > 0 {
		out = append(out, Finding{Rule: "agentfile.partial", Category: CatSkill, Severity: Low, Verdict: Info, Path: "",
			Title:    "给 AI 看的说明文件超过 " + strconv.Itoa(r.Limits.MaxFiles) + " 个，这一轮只查了前 " + strconv.Itoa(r.Limits.MaxFiles) + " 个",
			Evidence: map[string]string{"more": strconv.Itoa(found.More), "how": "下一轮还是先查前面这些"}})
	}
	if len(found.Left) > 0 {
		return nil, Skip(NotLooked(strings.Join(found.Left, "、")+" "), out...)
	}
	return out, nil
}
