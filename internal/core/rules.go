package core

// A rule registers a maker in an init() of its own file: Register("cache", NewCacheRule). The maker builds it for
// this Mac (l and f nil) or for a fake home (l the layout, f its fakes): there, every part that would ask this Mac
// (processes, system settings, Spotlight, launchctl…) answers from f, and only the fake home's own folders are looked at.
type RuleMaker func(l *Layout, f *Fakes) Rule

var makers = map[string]RuleMaker{}

// Register adds a rule's maker under its id.
func Register(id string, m RuleMaker) { makers[id] = m }

// RuleOrder is the order rules run in (as the Swift version's Scanner.defaultRules).
var RuleOrder = []string{"space.low", "space", "space.system", "space.duplicates", "cache.rebuildable", "leak.temp-prefix",
	"leftover.app-data", "leftover.installer", "stale.project", "stale.large-file", "persistence.launchagent-missing",
	"persistence.review", "startup", "apps.new", "process", "keyboard", "exposure", "secrets", "browser", "mcp", "skill",
	"agentfile", "permission.stale-grant", "posture", "malware",
	"supplychain.malicious"}

func build(l *Layout, f *Fakes) []Rule {
	var out []Rule
	for _, id := range RuleOrder {
		if m, ok := makers[id]; ok {
			out = append(out, m(l, f))
		}
	}
	return out
}

// DefaultRules are the rules of a round on this Mac.
func DefaultRules() []Rule { return build(nil, nil) }

// FixtureRules are the rules for a fake home, the machine-dependent parts answered from its fakes.
func FixtureRules(l Layout, f *Fakes) []Rule {
	if f == nil {
		f = &Fakes{}
	}
	return build(&l, f)
}
