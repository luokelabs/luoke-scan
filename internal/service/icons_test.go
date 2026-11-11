package service

import (
	"encoding/json"
	"testing"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// Every rule's findings get an icon of their own kind, and every icon the scan names is one the window draws.
func TestEveryRuleHasAnIcon(t *testing.T) {
	for _, r := range core.DefaultRules() {
		for _, e := range append([]string{r.ID()}, r.Emits()...) {
			icon, listed := ruleIcon(e)
			if !listed {
				t.Errorf("%s (rule %s) has no icon of its own", e, r.ID())
			}
			if !LucideIcons[icon] {
				t.Errorf("%s: %q is not an icon the window draws", e, icon)
			}
		}
	}
	for k, icon := range ruleIcons {
		if !LucideIcons[icon] {
			t.Errorf("ruleIcons[%s] = %q", k, icon)
		}
	}
	for k, icon := range choiceIcons {
		if !LucideIcons[icon] {
			t.Errorf("choiceIcons[%s] = %q", k, icon)
		}
	}
	for rule, want := range map[string]string{"cache.rebuildable.pip": "refresh-cw", "space.duplicates": "copy",
		"leftover.installer": "package", "leftover.app-data": "app-window", "malware.clamav": "shield-alert",
		"posture.filevault": "lock", "posture.firewall": "shield-check", "no.such": "file"} {
		if got, _ := ruleIcon(rule); got != want {
			t.Errorf("ruleIcon(%s) = %s, want %s", rule, got, want)
		}
	}
}

func TestFeaturesFromTheRequest(t *testing.T) {
	var meta O
	json.Unmarshal([]byte(`{"io.modelcontextprotocol/clientCapabilities": {"experimental": {"ai.luoke/a2ui":
		{"features": ["lucide", "collapsed", 3]}}}}`), &meta)
	f := Features(meta)
	if !f["lucide"] || !f["collapsed"] || len(f) != 2 {
		t.Errorf("%v", f)
	}
	if len(Features(O{})) != 0 || len(Features(O{metaCapabilities: "x"})) != 0 {
		t.Error("an older core lists none")
	}
}

// Without the forms the core knows, a fold is a caption and what follows; with collapsed, one folded Column.
func TestCollapsedFoldsOnlyWhereDrawn(t *testing.T) {
	plain := NewCard("x")
	plain.Text("a")
	plain.Collapsed("还有 1 项", func() { plain.Text("b") })
	comps, _ := cardParts(t, plain.Messages())
	if ts := texts(comps); len(ts) != 3 || ts[1] != "还有 1 项" || ts[2] != "b" {
		t.Errorf("without collapsed: %q", ts)
	}
	folded := NewCard("x").Use(map[string]bool{"collapsed": true})
	folded.Text("a")
	folded.Collapsed("还有 1 项", func() { folded.Text("b") })
	comps, _ = cardParts(t, folded.Messages())
	root := comps[0]["children"].([]any)
	if len(root) != 2 || root[1] != "fold1" {
		t.Fatalf("root %v", root)
	}
	for _, c := range comps {
		if c["id"] == "fold1" && (c["collapsed"] != "还有 1 项" || len(c["children"].([]any)) != 1) {
			t.Errorf("fold %v", c)
		}
	}
}

// The scan page in the forms a core with #67 and itemIcons draws: sections with an icon, items as one row (icon, title,
// size tag, detail; the choice or buttons on the right), the options' icons. Every icon is one the window draws.
func TestScanPageItemRows(t *testing.T) {
	pc := newPageCase(t)
	s := pc.s
	all := map[string]bool{"lucide": true, "collapsed": true, "optionIcons": true, "badge": true, "itemIcons": true}
	comps, _ := cardParts(t, s.page("overview", s.state(), all))
	byID := map[string]map[string]any{}
	for _, c := range comps {
		byID[c["id"].(string)] = c
	}
	icons, sections, rows, tagged := map[string]bool{}, 0, 0, 0
	for _, c := range comps {
		switch c["component"] {
		case "Icon":
			icons[c["name"].(string)] = true
			if !LucideIcons[c["name"].(string)] {
				t.Errorf("icon %q", c["name"])
			}
		case "Row":
			kids := c["children"].([]any)
			if c["justify"] == "spaceBetween" && byID[kids[0].(string)]["component"] == "Row" { // not the numbers on top
				rows++
				left := byID[kids[0].(string)]
				lk := left["children"].([]any)
				if byID[lk[0].(string)]["component"] != "Icon" || byID[lk[1].(string)]["component"] != "Column" {
					t.Errorf("item row %v", c)
				}
			} else if len(kids) == 2 && byID[kids[0].(string)]["component"] == "Icon" && byID[kids[1].(string)]["component"] == "Text" {
				sections++
			}
		case "Text":
			if c["variant"] == "badge" {
				tagged++
			}
		case "ChoicePicker":
			for _, o := range c["options"].([]any) {
				if o.(map[string]any)["icon"] == nil {
					t.Errorf("option without icon %v", o)
				}
			}
		}
	}
	for _, want := range []string{"trash-2", "eye", "refresh-cw", "package", "file", "puzzle"} {
		if !icons[want] {
			t.Errorf("no %s icon: %v", want, icons)
		}
	}
	if sections < 2 || rows < 4 || tagged < 2 {
		t.Errorf("sections %d, item rows %d, size tags %d", sections, rows, tagged)
	}
	// An older core gets the page as before: no icon, no row of an item
	old, _ := cardParts(t, s.page("overview", s.state()))
	for _, c := range old {
		if c["component"] == "Icon" || c["collapsed"] != nil {
			t.Errorf("older core got %v", c)
		}
	}
}
