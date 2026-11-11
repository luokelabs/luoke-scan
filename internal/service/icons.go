package service

import "strings"

// What the agent core can draw beyond version 1 of the card catalog (tool protocol §4 「后加的写法」): each request's
// _meta carries clientCapabilities.experimental["ai.luoke/a2ui"].features, the names of the forms it knows. A card
// uses a form only when its name is there; an older core lists none and gets the cards as before.

const metaCapabilities = "io.modelcontextprotocol/clientCapabilities"

// Features: the forms the agent core that sent this request draws; empty for an older core or none given.
func Features(meta O) map[string]bool {
	out := map[string]bool{}
	caps, _ := meta[metaCapabilities].(map[string]any)
	exp, _ := caps["experimental"].(map[string]any)
	a2ui, _ := exp["ai.luoke/a2ui"].(map[string]any)
	list, _ := a2ui["features"].([]any)
	for _, x := range list {
		if name, ok := x.(string); ok {
			out[name] = true
		}
	}
	return out
}

// LucideIcons are the icon names the agent's window draws (§4 「后加的写法」 lucide): a card names no other, and names
// these only when the core lists "lucide".
var LucideIcons = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`app-window archive brain calendar calendar-plus check chevron-down chevron-right
		circle-help circle-minus clock copy cpu eye file folder folder-open globe hard-drive inbox info key keyboard
		lightbulb link lock mail package pencil-line power puzzle refresh-cw reply settings shield-alert shield-check
		sparkles square-arrow-out-up-right star trash-2 trending-up triangle-alert user x`) {
		LucideIcons[n] = true
	}
}

// ruleIcons: the icon in front of a finding's line on the scan page (luoke-scan#129), by the longest listed name its
// rule id is or starts with followed by a dot ("cache" covers cache.rebuildable.pip). Every rule's findings are
// covered (TestEveryRuleHasAnIcon); ruleIcon still falls back to "file", so no line is drawn without one.
var ruleIcons = map[string]string{
	"agentfile":                     "puzzle",
	"apps":                          "app-window",
	"browser":                       "globe",
	"cache":                         "refresh-cw",
	"deps":                          "package",
	"exposure":                      "key",
	"keyboard":                      "keyboard",
	"leak":                          "folder-open",
	"leftover":                      "app-window",
	"leftover.installer":            "package",
	"leftover.partial-download":     "file",
	"leftover.relocated-items":      "folder",
	"leftover.intel-homebrew":       "package",
	"leftover.intel-homebrew-links": "link",
	"malware":                       "shield-alert",
	"mcp":                           "key",
	"model.chat-template":           "sparkles",
	"permission":                    "app-window",
	"persistence":                   "power",
	"pkg":                           "package",
	"posture":                       "shield-check",
	"posture.filevault":             "lock",
	"posture.screen-lock":           "lock",
	"process":                       "cpu",
	"secrets":                       "key",
	"skill":                         "puzzle",
	"space":                         "hard-drive",
	"space.ai-model":                "sparkles",
	"space.duplicates":              "copy",
	"space.growth":                  "trending-up",
	"stale":                         "folder",
	"stale.large-file":              "file",
	"stale.project":                 "folder",
	"startup":                       "power",
	"supplychain":                   "package",
	"vitals":                        "cpu",
	"vitals.battery":                "power",
	"vitals.thermal":                "triangle-alert",
}

// ruleIcon: the icon for a rule's findings, and whether the table has it (false: the fallback).
func ruleIcon(rule string) (string, bool) {
	best, icon := "", "file"
	for p, i := range ruleIcons {
		if len(p) > len(best) && (rule == p || strings.HasPrefix(rule, p+".")) {
			best, icon = p, i
		}
	}
	return icon, best != ""
}

// choiceIcons: what a choice's option shows next to its words when the core draws option icons (optionIcons).
var choiceIcons = map[string]string{ChoiceTrash: "trash-2", ChoiceKeep: "circle-minus", ChoiceIgnore: "x",
	ChoiceClone: "copy", ChoiceDelete: "trash-2", ChoiceRemove: "refresh-cw"}

// lucideNames: the version 1 icon names buttons use, as Lucide names (§4 lucide).
var lucideNames = map[string]string{"trash": "trash-2", "warning": "triangle-alert", "close": "x", "question": "circle-help"}
