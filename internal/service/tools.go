package service

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// AutoKind and its labels live in core (the picker is there).
type AutoKind = core.AutoKind

var AutoKinds = core.AutoKinds

// Settings pages (x-apple.systempreferences deep links) by the grant's name: the grants a stale-grant finding names
// (core.GrantPages), and FileVault.
var settingsPages = func() map[string]string {
	m := map[string]string{"FileVault": "FDE"}
	for g, p := range core.GrantPages {
		m[g] = p
	}
	return m
}()

const (
	loginItemsGrant = "登录项"
	loginItemsURL   = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
)

// settingsPane is the page's name the main body knows (HostRequests.settingsPanes in luoke-core), and its address.
func settingsPane(grant string) (pane, url string, ok bool) {
	switch grant {
	case loginItemsGrant:
		return "LoginItems", loginItemsURL, true
	case batteryGrant: // 运行状况（luoke-scan#126）：本体不认这两个时由扫描自己 open
		return "Battery", batteryURL, true
	case activityMonitorGrant:
		return "ActivityMonitor", activityMonitorApp, true
	}
	if p, ok := settingsPages[grant]; ok {
		return p, "x-apple.systempreferences:com.apple.preference.security?" + p, true
	}
	return "", "", false
}

func settingsURL(grant string) (string, bool) {
	_, url, ok := settingsPane(grant)
	return url, ok
}

func (s *Service) register() {
	srv := s.Server
	srv.ResourceMeta(s.OutboxURI(), "扫描要告诉你的事", func(meta O) any { return s.outbox(Features(meta)) })
	s.registerPages()
	srv.Tool("scan_status", ToolSpec{Title: "扫描的状态", Description: "上一轮什么时候查的、查出多少、病毒库日期、哪些项没查成", ReadOnly: true},
		func(_ O, meta O) (ToolOutput, error) { return s.status(meta, s.state()) })
	srv.Tool("scan_findings", ToolSpec{Title: "列出发现", Description: "上一轮的发现，可以按结论、类别筛", ReadOnly: true,
		Properties: O{"verdict": O{"type": "string", "enum": A{"safe", "confirm", "info"}},
			"category": O{"type": "string"}, "limit": O{"type": "integer", "minimum": 1, "maximum": 50}}},
		func(args O, meta O) (ToolOutput, error) { return s.findings(args, meta, s.state()) })
	srv.Tool("scan_now", ToolSpec{Title: "现在查一下", Description: "马上开始一轮扫描（只读，不改动任何东西）", ReadOnly: true},
		func(O, O) (ToolOutput, error) { return s.scanNow() })
	srv.Tool("scan_plan", ToolSpec{Title: "出清理方案", Description: "按上一轮的发现出一份清理方案，每项可以选移到废纸篓、先不动、以后别提", ReadOnly: true,
		Properties: O{"scope": O{"type": "string", "enum": A{"all", "cache"}}}},
		func(args O, _ O) (ToolOutput, error) { return s.planTool(args, s.state()) })
	srv.Tool("scan_apply", ToolSpec{Title: "执行清理方案", Description: "执行用户在卡片上点过的方案：只做方案里列的、用户选的",
		Properties: O{"plan_id": O{"type": "string"}, "choices": O{"type": "object"}}, Required: []string{"plan_id", "choices"}, Destructive: true},
		func(args O, meta O) (ToolOutput, error) { return s.apply(args, meta) })
	srv.Tool("scan_ignore", ToolSpec{Title: "以后别提这一条", Description: "把一条发现标成不用管，以后不再报；undo 为真时撤销，照样提醒",
		Properties: O{"finding_id": O{"type": "string"}, "undo": O{"type": "boolean", "description": "撤销刚才的「以后别提」"}}, Required: []string{"finding_id"}},
		func(args O, meta O) (ToolOutput, error) { return s.ignore(args, meta) })
	srv.Tool("scan_restore", ToolSpec{Title: "放回",
		Description: "把清理时移进废纸篓的放回原处：一条清理记录（c-…），或一次清理的整批（p-… / auto-…）；原位置有同名的就放在旁边，不盖掉",
		Properties:  O{"id": O{"type": "string"}}, Required: []string{"id"}},
		func(args O, meta O) (ToolOutput, error) { return s.restoreTool(args, meta) })
	srv.Tool("scan_autoclean", ToolSpec{Title: "自动清理", Description: "开或关不用点就清的四类：会重建的缓存、装好了的应用的安装包、下载文件夹里的重复文件、测试工具留下的临时文件夹",
		Properties: O{"on": O{"type": "boolean", "description": "开（true）还是关（false）；要给"},
			"enable": O{"type": "boolean", "description": "旧写法，和 on 一样；给了 on 就不看它"}}},
		func(args O, meta O) (ToolOutput, error) { return s.setAutoclean(args, meta) })
	srv.Tool("scan_reveal", ToolSpec{Title: "在访达里显示", Description: "在访达里选中一条发现指的文件或文件夹", ReadOnly: true,
		Properties: O{"finding_id": O{"type": "string"}}, Required: []string{"finding_id"}, MacOnly: true},
		func(args O, _ O) (ToolOutput, error) { return s.reveal(args) })
	srv.Tool("scan_explain", ToolSpec{Title: "让本机模型说说这一项", Description: "请这台 Mac 上的模型用一两句话解释一条发现（只是说明，不改结论；要几秒到几十秒）", ReadOnly: true,
		Properties: O{"finding_id": O{"type": "string"}}, Required: []string{"finding_id"}},
		func(args O, _ O) (ToolOutput, error) { return s.explainOne(args) })
	srv.Tool("scan_open_settings", ToolSpec{Title: "打开系统设置", Description: "打开系统设置里对应的页面（隐私与安全性的某个权限、「登录项」或「电池」），或者打开活动监视器", ReadOnly: true,
		Properties: O{"grant": O{"type": "string"}}, Required: []string{"grant"}, MacOnly: true},
		func(args O, _ O) (ToolOutput, error) { return s.openSettings(args) })
	srv.Tool("outbox_ack", ToolSpec{Title: "记下说过了", Description: "agent 告诉扫描某件事已经说过、答过或放下了", ReadOnly: true,
		Properties: O{"id": O{"type": "string"}, "state": O{"type": "string", "enum": A{"shown", "answered", "dismissed"}}},
		Required:   []string{"id", "state"}},
		func(args O, _ O) (ToolOutput, error) { return s.ack(args) })
}

func (s *Service) status(meta O, st State) (ToolOutput, error) {
	r := s.Store.LastReport()
	if r == nil {
		return ToolOutput{Text: "还没查过。", Card: s.answerCard(meta, false, func(c *Card) {
			c.Text("还没查过这台 Mac。")
			c.Buttons([]Button{{Label: "现在查一下", Event: "scan_now", Primary: true}})
		})}, nil
	}
	f := s.visible(*r, st)
	count := map[core.Verdict]int{}
	var reclaim int64
	for _, x := range f {
		count[x.Verdict]++
		if x.Verdict == core.Safe && x.Bytes != nil {
			reclaim += *x.Bytes
		}
	}
	scanning := s.IsScanning()
	lines := []string{fmt.Sprintf("上一轮：%s，用了 %d 秒", core.ISOTime(r.StartedAt.Time), int(r.FinishedAt.Sub(r.StartedAt.Time).Seconds())),
		fmt.Sprintf("发现：放心删 %d、要确认 %d、仅供参考 %d", count[core.Safe], count[core.Confirm], count[core.Info])}
	if reclaim > 0 {
		lines = append(lines, "放心删的能腾出 "+core.FormatBytes(reclaim))
	}
	if v, ok := r.Versions["clamav_db_version"]; ok {
		d, ok := r.Versions["clamav_db_date"]
		if !ok {
			d = "日期不明"
		}
		lines = append(lines, fmt.Sprintf("病毒库 daily %s（%s）", v, d))
	}
	if len(r.Skipped) > 0 {
		var names []string
		for _, x := range r.Skipped {
			names = append(names, x.Rule)
		}
		lines = append(lines, "没查成："+strings.Join(names, "、"))
	}
	var on []string
	for _, k := range AutoKinds {
		if _, off := st.AutoOff[string(k)]; !off {
			on = append(on, k.Label())
		}
	}
	if st.AutocleanOff != nil || len(on) == 0 {
		lines = append(lines, "自动清：关")
	} else {
		lines = append(lines, "自动清："+strings.Join(on, "、"))
	}
	if scanning {
		what, _ := s.scanProgress(r)
		lines = append(lines, "现在正在查（"+what+"）")
	}
	return ToolOutput{Text: strings.Join(lines, "；"), Card: s.answerCard(meta, false, func(c *Card) {
		c.Heading("扫描")
		for i, l := range lines {
			c.Text(l, i != 0)
		}
		if !scanning {
			c.Buttons([]Button{{Label: "现在查一下", Event: "scan_now"}})
		}
	})}, nil
}

func intArg(v any) (int, bool) {
	switch x := v.(type) {
	case int64:
		return int(x), true
	case float64:
		if x == float64(int(x)) {
			return int(x), true
		}
	case int:
		return x, true
	}
	return 0, false
}

func (s *Service) findings(args, meta O, st State) (ToolOutput, error) {
	r := s.Store.LastReport()
	if r == nil {
		return ToolOutput{}, Fail("not_ready", "还没查过，先查一轮。")
	}
	f := s.visible(*r, st)
	if v, ok := args["verdict"].(string); ok {
		if v != "safe" && v != "confirm" && v != "info" {
			return ToolOutput{}, Fail("invalid", "verdict 只能是 safe、confirm、info")
		}
		var keep []core.Finding
		for _, x := range f {
			if string(x.Verdict) == v {
				keep = append(keep, x)
			}
		}
		f = keep
	}
	if cat, ok := args["category"].(string); ok {
		var keep []core.Finding
		for _, x := range f {
			if string(x.Category) == cat {
				keep = append(keep, x)
			}
		}
		f = keep
	}
	limit := 20
	if n, ok := intArg(args["limit"]); ok {
		limit = n
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 50 {
		limit = 50
	}
	shown := f
	if len(shown) > limit {
		shown = shown[:limit]
	}
	var text string
	if len(shown) == 0 {
		text = "没有这样的发现。"
	} else {
		var lines []string
		for _, x := range shown {
			lines = append(lines, "["+marks[x.Verdict]+"] "+x.Title)
		}
		text = strings.Join(lines, "\n")
		if len(f) > limit {
			text += fmt.Sprintf("\n另有 %d 条", len(f)-limit)
		}
	}
	return ToolOutput{Text: text, Card: s.answerCard(meta, false, func(c *Card) {
		if len(shown) == 0 {
			c.Heading("没有这样的发现")
		} else {
			c.Heading(fmt.Sprintf("发现 %d 条", len(f)))
		}
		for _, x := range shown {
			c.Text("[" + marks[x.Verdict] + "] " + x.Title)
			var detail []string
			if x.Path != "" {
				detail = append(detail, s.display(x.Path))
			}
			for _, k := range []string{"would_lose", "hint", "how"} {
				if v, ok := x.Evidence[k]; ok {
					detail = append(detail, v)
				}
			}
			detail = append(detail, modelLines(x)...)
			if len(detail) > 0 {
				c.Text(strings.Join(detail, "\n"), true)
			}
		}
		if len(f) > limit {
			c.Text(fmt.Sprintf("另有 %d 条", len(f)-limit), true)
		}
	})}, nil
}

func (s *Service) scanNow() (ToolOutput, error) {
	if s.Config.StartScan != nil {
		if s.IsScanning() {
			return ToolOutput{Text: "已经在查了，查完结果会更新。", Extra: O{"data": O{"type": "scan-started", "already": true}}}, nil
		}
		if !s.Config.StartScan() {
			return ToolOutput{}, Fail("failed", "没能开始查。")
		}
		s.waitStarted(3 * time.Second)
	} else {
		lock := core.TakeLock(s.Store.Dir, "round.lock", 0)
		if lock == nil {
			return ToolOutput{Text: "已经在查了，查完结果会更新。", Extra: O{"data": O{"type": "scan-started", "already": true}}}, nil
		}
		go func() {
			s.RunRound(false)
			lock.Release()
		}()
	}
	return ToolOutput{Text: "开始查了，一般几分钟；查完结果会更新。只读，不改动任何东西。",
		Extra: O{"data": O{"type": "scan-started", "already": false}}}, nil
}

func (s *Service) ignore(args, meta O) (ToolOutput, error) {
	id, _ := args["finding_id"].(string)
	if id == "" || len([]rune(id)) >= 300 {
		return ToolOutput{}, Fail("invalid", "finding_id 不对")
	}
	undo, _ := args["undo"].(bool)
	changed := false
	at := s.now()
	s.mutate(func(st *State) {
		_, had := st.Ignored[id]
		if undo {
			changed = had
			delete(st.Ignored, id)
		} else {
			changed = !had
			st.Ignored[id] = core.Time{Time: at}
		}
	})
	report := s.Store.LastReport()
	var f *core.Finding
	if report != nil {
		for i := range report.Findings {
			if s.fid(report.Findings[i]) == id {
				f = &report.Findings[i]
				break
			}
		}
	}
	// The answer as data (top-level ADR 0028): which finding, by its rule; a recognised file by its name.
	data := O{"type": "ignored", "finding": id, "undo": undo, "rule": "", "name": ""}
	if f != nil {
		data["rule"] = f.Rule
		if isMalware(*f) {
			data["name"] = filepath.Base(f.Path)
		}
	}
	name := "这一条"
	if f != nil {
		name = "「" + f.Title + "」"
		if isMalware(*f) {
			name = "「" + filepath.Base(f.Path) + "」" // 报毒的卡片上写的是文件名
		}
	}
	if undo {
		if changed && f != nil {
			s.remember([]MemoryRecord{s.unignoredRecord(*f)})
		}
		text := "撤销了，" + name + "还会提醒你。"
		return ToolOutput{Text: text, Card: s.answerCard(meta, false, func(c *Card) { c.Text(text) }), Done: Bool(true),
			Extra: O{"data": data}}, nil
	}
	if changed && f != nil {
		s.remember([]MemoryRecord{s.ignoredRecord(*f, report)})
	}
	// 在原来那张卡的位置留一行，点错了能撤销（设计评审 11-07：「不是病毒」就在垃圾桶旁边，自己下载的文件很可能就点它）
	text := "已记下：" + name + "以后不再提醒。"
	return ToolOutput{Text: text, Card: s.answerCard(meta, false, func(c *Card) {
		c.ButtonsAfter(text, []Button{{Label: "撤销", Event: "scan_ignore", Context: O{"finding_id": id, "undo": true}}})
	}), Done: Bool(true), Extra: O{"data": data}}, nil
}

func (s *Service) setAutoclean(args, meta O) (ToolOutput, error) {
	var on bool
	var ok bool
	if v, has := args["on"]; has {
		on, ok = v.(bool)
	} else {
		on, ok = args["enable"].(bool)
	}
	if !ok {
		return ToolOutput{}, Fail("invalid", "on 要是真或假")
	}
	at := s.now()
	var stillOff []AutoKind
	changed := false
	s.mutate(func(st *State) {
		was := st.AutocleanOff == nil
		allOff := len(st.AutoOff) > 0
		for _, k := range AutoKinds {
			_, off := st.AutoOff[string(k)]
			allOff = allOff && off
		}
		if on && (st.AutocleanOff != nil || allOff) { // 每一类都关了时开关画成关：打开就是都打开
			st.AutoOff = nil
		}
		if on {
			st.AutocleanOff = nil
		} else if st.AutocleanOff == nil {
			t := core.Time{Time: at}
			st.AutocleanOff = &t
		}
		if on {
			for _, k := range AutoKinds {
				if _, off := st.AutoOff[string(k)]; off {
					stillOff = append(stillOff, k)
				}
			}
		}
		changed = was != on || (on && allOff)
	})
	var onKinds []string
	for _, k := range AutoKinds {
		off := false
		for _, x := range stillOff {
			if x == k {
				off = true
			}
		}
		if !off {
			onKinds = append(onKinds, k.Label())
		}
	}
	text := "好，以后都先问你再清。"
	if on {
		text = "好，以后" + strings.Join(onKinds, "、") + "查到就清，清完告诉你；移进废纸篓的能放回。"
	}
	if len(stillOff) > 0 {
		var names []string
		for _, k := range stillOff {
			names = append(names, k.Label())
		}
		text += strings.Join(names, "、") + "你放回过，还是先问你。"
	}
	if changed {
		s.remember([]MemoryRecord{s.autocleanRecord(on)})
	}
	round := s.roundRedraw(meta)
	waits := round != nil && round.waits
	card := s.answerCard(meta, waits, func(c *Card) {
		c.Text(text)
		if round != nil {
			round.body(c)
		}
	})
	// The answer as data (top-level ADR 0028): the kinds cleaned without asking from now on, and those the user put
	// back before, which stay off; round: the round's card as it is now, when the click came from it.
	var onCodes, offCodes []string
	for _, k := range AutoKinds {
		off := !on
		for _, x := range stillOff {
			if x == k {
				off = true
			}
		}
		if off && on {
			offCodes = append(offCodes, string(k))
		} else if on {
			onCodes = append(onCodes, string(k))
		}
	}
	data := O{"type": "autoclean", "on": on, "kinds": strs(onCodes), "keptOff": strs(offCodes), "round": nil}
	if round != nil {
		data["round"] = round.data
	}
	return ToolOutput{Text: text, Card: card, Done: Bool(!waits), Extra: O{"data": data}}, nil
}

func (s *Service) reveal(args O) (ToolOutput, error) {
	id, _ := args["finding_id"].(string)
	var target string
	if r := s.Store.LastReport(); r != nil {
		for _, f := range r.Findings {
			if s.fid(f) == id && strings.HasPrefix(f.Path, "/") {
				target = s.revealTarget(f)
				break
			}
		}
	}
	if target == "" || !core.Exists(target) {
		return ToolOutput{}, Fail("stale", "这一条指的东西已经不在了。")
	}
	// 螺壳 is in front: it can bring Finder forward, this process cannot (host.go)
	if !s.front("reveal", map[string]any{"path": target}) && s.Config.Command("/usr/bin/open", []string{"-R", target}) != 0 {
		return ToolOutput{}, Fail("failed", "访达没打开。")
	}
	return ToolOutput{Text: "在访达里选中了 " + s.display(target) + "。",
		Extra: O{"data": O{"type": "revealed", "path": s.display(target)}}}, nil
}

// revealTarget: what 「在访达里显示」 selects for a finding: its path; the folder of a pattern of temp folders
// (…/wings-*); a model's chat template, the template file itself rather than the model's whole folder (luoke-scan#152).
// "" when it has no place on the disk.
func (s *Service) revealTarget(f core.Finding) string {
	if !strings.HasPrefix(f.Path, "/") {
		return ""
	}
	target := f.Path
	if strings.HasSuffix(target, "-*") {
		target = dirOfPath(target)
	}
	if t := s.expandHome(f.Evidence["template"]); strings.HasPrefix(f.Rule, "model.chat-template") && strings.HasPrefix(t, f.Path+"/") {
		target = t
	}
	return target
}

func (s *Service) front(method string, params map[string]any) bool {
	return s.Config.Front != nil && s.Config.Front(method, params)
}

// expandHome: 「~/…」 in the home this service looks at; anything else as it is.
func (s *Service) expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(s.Config.Context.Home, rest)
	}
	return p
}

func dirOfPath(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return "/"
}

func (s *Service) openSettings(args O) (ToolOutput, error) {
	grant, _ := args["grant"].(string)
	pane, url, ok := settingsPane(grant)
	if !ok {
		return ToolOutput{}, Fail("invalid", "不认识这个权限")
	}
	if !s.front("open_settings", map[string]any{"pane": pane}) && s.Config.Command("/usr/bin/open", []string{url}) != 0 {
		return ToolOutput{}, Fail("failed", "系统设置没打开。")
	}
	// grant: the name the button sent (a System Settings page as macOS names it, or the Activity Monitor)
	data := O{"data": O{"type": "opened", "what": pane, "activityMonitor": grant == activityMonitorGrant}}
	if grant == activityMonitorGrant {
		return ToolOutput{Text: "打开了活动监视器。", Extra: data}, nil
	}
	return ToolOutput{Text: "打开了系统设置的「" + grant + "」页。", Extra: data}, nil
}

func (s *Service) ack(args O) (ToolOutput, error) {
	id, _ := args["id"].(string)
	st, _ := args["state"].(string)
	if id == "" || len([]rune(id)) >= 300 || (st != "shown" && st != "answered" && st != "dismissed") {
		return ToolOutput{}, Fail("invalid", "id 或 state 不对")
	}
	at := s.now()
	s.mutate(func(state *State) {
		if _, had := state.Acks[id]; st != "shown" || !had {
			state.Acks[id] = Ack{State: st, At: core.Time{Time: at}}
		}
		if strings.HasPrefix(id, "round/") {
			if start, err := time.Parse(time.RFC3339, strings.TrimPrefix(id, "round/")); err == nil {
				told := map[string]bool{}
				for _, d := range carried(start, *state) {
					told[d.ID] = true
				}
				for i := range state.AutoDone {
					if told[state.AutoDone[i].ID] && state.AutoDone[i].Told == nil {
						t := core.Time{Time: at}
						state.AutoDone[i].Told = &t
					}
				}
			}
		}
	})
	return ToolOutput{Text: "记下了。"}, nil
}

// uniq keeps the first of each.
func uniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

var _ = sort.Strings
