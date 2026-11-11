package core

import (
	"sort"
	"strconv"
	"strings"
)

// SkillRule: the AI agents' skills on this Mac (folders with a SKILL.md: personal ones in the home, and a project's
// own), each read within bounds and checked statically (skillcheck.go) for what a malicious or careless skill does.
// One finding per skill with something to say, only for reference: a skill is something the user chose to install,
// so nothing is planned, cleaned or deleted. Nothing of a skill's contents is kept, and what is reported is where and
// what kind, never the text that matched. Only luoke-core's local model sees some of it: a shortened excerpt of a
// reported skill (internal/service/hubtask.go), which stays on this Mac.
type SkillRule struct {
	Places []SkillPlace
	Limits SkillLimits
}

func init() { Register("skill", NewSkillRule) }

// NewSkillRule is the same for this Mac and a fake home: it only reads files.
func NewSkillRule(l *Layout, f *Fakes) Rule {
	return &SkillRule{Places: SkillPlaces, Limits: DefaultSkillLimits()}
}

func (r *SkillRule) ID() string      { return "skill" }
func (r *SkillRule) Emits() []string { return []string{"skill"} }

// skillPriority: which concern names a finding when several are as serious.
var skillPriority = []SignalKind{SignalExfil, SignalDownloadExec, SignalPersistence, SignalAgentTamper, SignalEscalation, SignalDestructive,
	SignalInjection, SignalPermission, SignalSupplyChain, SignalUnreadable}

func signalRank(k SignalKind) int {
	for i, p := range skillPriority {
		if p == k {
			return i
		}
	}
	return len(skillPriority)
}

func skillHow(top SignalKind, sev Severity) string {
	base := "不认识就在访达里把这个 skill 的文件夹移到废纸篓；认得的话看看它为什么要这样做"
	switch top {
	case SignalExfil:
		return base + "；用过的话，把它可能读过的密钥、令牌换新的"
	case SignalDownloadExec, SignalDestructive:
		return base + "；弄清楚之前别让 AI 用它"
	case SignalPersistence:
		return base + "；用过的话，看看 ~/Library/LaunchAgents、crontab -l 和 shell 的启动文件里有没有多出来的东西"
	case SignalAgentTamper:
		if sev == Low {
			return "它会改 AI 工具自己的东西；认得、用得着就留着，不认识就移到废纸篓"
		}
		return base + "；用过的话，看看 AI 工具的设置（钩子、MCP 服务器）和 CLAUDE.md 这类文件有没有被改"
	case SignalEscalation:
		return base + "；用过的话，看看 系统设置 → 隐私与安全性 里有没有被改"
	case SignalInjection:
		return base + "；可以用文本编辑器打开那个文件，看看那几行"
	case SignalPermission:
		if sev == Low {
			return "认得的话，可以在 SKILL.md 的 allowed-tools 里把 Bash 限定到它要用的命令（例如 Bash(git status:*)）"
		}
		return base
	case SignalSupplyChain:
		if sev == Low {
			return "认得的话，让它装包时写上版本号（例如 包名==1.2.3、包名@1.2.3）；不认识就移到废纸篓"
		}
		return base
	}
	return "里面有文字检查看不到的内容；不认识它的来源，就把这个 skill 的文件夹移到废纸篓"
}

// orderedSignals are the signals that count, the most serious (then by priority) first, and the most serious severity.
func orderedSignals(signals []SkillSignal) (counted []SkillSignal, top Severity) {
	for _, s := range signals {
		if s.Severity != "" {
			counted = append(counted, s)
			if top == "" || s.Severity.Rank() > top.Rank() {
				top = s.Severity
			}
		}
	}
	sort.SliceStable(counted, func(i, j int) bool {
		a, b := counted[i], counted[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return signalRank(a.Kind) < signalRank(b.Kind)
	})
	return counted, top
}

// signalSummary is what was found, for the evidence: the first eight, counted ones first, at most 900 Characters.
func signalSummary(ordered, signals []SkillSignal) string {
	all := append([]SkillSignal{}, ordered...)
	for _, s := range signals {
		if s.Severity == "" {
			all = append(all, s)
		}
	}
	var parts []string
	for i, s := range all {
		if i >= 8 {
			break
		}
		parts = append(parts, s.Label+signalPlace(s))
	}
	return aiCut(strings.Join(parts, "；"), 900)
}

func distinctLabels(signals []SkillSignal) int {
	seen := map[string]bool{}
	for _, s := range signals {
		seen[s.Label] = true
	}
	return len(seen)
}

func signalKinds(signals []SkillSignal) string {
	var ks []string
	for _, s := range signals {
		ks = append(ks, string(s.Kind))
	}
	return strings.Join(aiSortedUnique(ks), ",")
}

func skillAlsoText(also []string) string {
	n := len(also)
	if n > 3 {
		also = also[:3]
	}
	s := strings.Join(also, "；")
	if n > 3 {
		s += " 等 " + strconv.Itoa(n) + " 处"
	}
	return s
}

// SkillFinding is the finding for a skill, or nil when nothing it found counts on its own. also: the same skill
// elsewhere, as shown.
func SkillFinding(skill Skill, signals []SkillSignal, also []string) *Finding {
	ordered, severity := orderedSignals(signals)
	if severity == "" {
		return nil
	}
	top := ordered[0]
	name := aiClean(skill.Name, 40)
	if name == "" {
		name = aiClean(aiNSLast(skill.Folder), 40)
	}
	concerns := distinctLabels(ordered)
	who := skill.Agent + " 的 skill「" + name + "」"
	if skill.Scope == ScopeProject && skill.Project != "" {
		who = "项目 " + aiClean(aiNSLast(skill.Project), 40) + " 里 " + who
	}
	title := who + "：" + top.Label
	if concerns > 1 {
		title += "，另有 " + strconv.Itoa(concerns-1) + " 处要看"
	}
	ev := map[string]string{"agent": skill.Agent, "scope": string(skill.Scope), "skill": name, "kinds": signalKinds(ordered),
		"why": "AI 用这个 skill 时会照着它的说明做、运行它带的脚本，用的是你的权限。查到：" + signalSummary(ordered, signals),
		"how": skillHow(top.Kind, severity)}
	if len(also) > 0 {
		ev["also"] = skillAlsoText(also)
	}
	// Keyed on the folder and its contents: a later change is a new finding, not hidden by a "以后别提" for this one.
	return &Finding{Rule: "skill." + string(top.Kind), Category: CatSkill, Severity: severity, Verdict: Info, Path: skill.Folder,
		Title: title, Evidence: ev, Key: skill.RealFolder + "|" + skill.Digest}
}

func (r *SkillRule) Run(ctx *Context) ([]Finding, error) {
	found := FindSkills(ctx, r.Places, r.Limits, true)
	if ctx.IsCancelled() {
		return nil, Skip(Interrupted)
	}
	// The same skill copied to several places (another agent's folder, a plugin's cache): said once.
	var order []string
	copies := map[string][]Skill{}
	for _, s := range found.Skills {
		if _, ok := copies[s.Digest]; !ok {
			order = append(order, s.Digest)
		}
		copies[s.Digest] = append(copies[s.Digest], s)
	}
	out := []Finding{}
	for _, d := range order {
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted, out...)
		}
		group := copies[d]
		var also []string
		for _, s := range group[1:] {
			also = append(also, ctx.Shown(s.Folder))
		}
		if f := SkillFinding(group[0], SkillSignals(group[0]), also); f != nil {
			out = append(out, *f)
		}
	}
	if found.More > 0 {
		out = append(out, Finding{Rule: "skill.partial", Category: CatSkill, Severity: Low, Verdict: Info, Path: "",
			Title:    "这台 Mac 上的 skill 超过 " + strconv.Itoa(r.Limits.MaxSkills) + " 个，这一轮只查了前 " + strconv.Itoa(r.Limits.MaxSkills) + " 个",
			Evidence: map[string]string{"more": strconv.Itoa(found.More), "how": "用不着的 skill 移到废纸篓；下一轮还是先查前面这些"}})
	}
	if len(found.Left) > 0 {
		return nil, Skip(NotLooked(strings.Join(found.Left, "、")+" "), out...)
	}
	return out, nil
}
