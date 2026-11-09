package service

import (
	"strconv"
	"strings"
)

// Card builds an A2UI v0.9 card for the agent (tool protocol §4): catalog ai.luoke/a2ui/agent/1, at most 200
// components, 2000 characters per text. The same shapes and ids as the Swift version (the agent keys on them).
type Card struct {
	SurfaceID  string
	prefix     string
	components []any
	top        []string
	choiceData map[string]O
	n          int
}

const (
	CardCatalog       = "ai.luoke/a2ui/agent/1"
	CardVersion       = "v0.9"
	CardMaxText       = 2000
	CardMaxComponents = 200
)

// ChoicesPath is the button context the agent replaces with the current choices; AdminChoicesPath, for the items
// that need the password.
var (
	ChoicesPath      = O{"path": "/choices"}
	AdminChoicesPath = O{"path": "/admin_choices"}
)

// Button on a card.
type Button struct {
	Label, Event string
	Context      O
	Primary      bool
}

func NewCard(surfaceID string, prefix ...string) *Card {
	c := &Card{SurfaceID: surfaceID, choiceData: map[string]O{}}
	if len(prefix) > 0 {
		c.prefix = prefix[0]
	}
	return c
}

// Count is the number of components including the root.
func (c *Card) Count() int { return len(c.components) + 1 }

// Clip keeps a text within 2000 characters.
func Clip(s string) string {
	r := []rune(s)
	if len(r) <= CardMaxText {
		return s
	}
	return string(r[:CardMaxText-1]) + "…"
}

func (c *Card) id(kind string) string {
	c.n++
	return c.prefix + kind + strconv.Itoa(c.n)
}

func (c *Card) add(comp O, top bool) {
	c.components = append(c.components, comp)
	if top {
		c.top = append(c.top, comp["id"].(string))
	}
}

func (c *Card) Heading(text string) {
	c.add(O{"id": c.id("h"), "component": "Text", "text": Clip(text), "variant": "h4"}, true)
}

func (c *Card) Text(text string, caption ...bool) {
	comp := O{"id": c.id("t"), "component": "Text", "text": Clip(text)}
	if len(caption) > 0 && caption[0] {
		comp["variant"] = "caption"
	}
	c.add(comp, true)
}

func (c *Card) Divider() { c.add(O{"id": c.id("d"), "component": "Divider"}, true) }

// Option of a choice.
type Option struct{ Value, Label string }

// Choice is one item with a choice of what to do; the current value lives at /<group>/<key> (a string array).
func (c *Card) Choice(key, label string, options []Option, selected string, group ...string) {
	g := "choices"
	if len(group) > 0 {
		g = group[0]
	}
	if c.choiceData[g] == nil {
		c.choiceData[g] = O{}
	}
	c.choiceData[g][key] = A{selected}
	opts := A{}
	for _, o := range options {
		opts = append(opts, O{"label": o.Label, "value": o.Value})
	}
	c.add(O{"id": c.prefix + "c-" + key, "component": "ChoicePicker", "label": Clip(label), "options": opts,
		"value": O{"path": "/" + g + "/" + key}}, true)
}

func (c *Card) Buttons(specs []Button) {
	var ids []any
	for _, b := range specs {
		bid := c.id("b")
		tid := bid + "-text"
		ctx := b.Context
		if ctx == nil {
			ctx = O{}
		}
		comp := O{"id": bid, "component": "Button", "child": tid, "action": O{"event": O{"name": b.Event, "context": ctx}}}
		if b.Primary {
			comp["variant"] = "primary"
		}
		c.add(comp, false)
		c.add(O{"id": tid, "component": "Text", "text": b.Label}, false)
		ids = append(ids, bid)
	}
	if ids == nil {
		ids = A{}
	}
	c.add(O{"id": c.id("r"), "component": "Row", "children": ids}, true)
}

func (c *Card) body() A {
	top := A{}
	for _, t := range c.top {
		top = append(top, t)
	}
	return append(A{O{"id": "root", "component": "Column", "children": top}}, c.components...)
}

// Messages is a new card: createSurface, the components, the data model.
func (c *Card) Messages() []any {
	return append([]any{O{"version": CardVersion, "createSurface": O{"surfaceId": c.SurfaceID, "catalogId": CardCatalog}}}, c.Updates(true)...)
}

// Updates replaces a card already shown; includeData false keeps the user's choices.
func (c *Card) Updates(includeData bool) []any {
	out := []any{O{"version": CardVersion, "updateComponents": O{"surfaceId": c.SurfaceID, "components": c.body()}}}
	if includeData && len(c.choiceData) > 0 {
		value := O{}
		for g, d := range c.choiceData {
			value[g] = d
		}
		out = append(out, O{"version": CardVersion, "updateDataModel": O{"surfaceId": c.SurfaceID, "path": "/", "value": value}})
	}
	return out
}

// CardLines is what a card says, for a terminal: its texts from the one equal to first up to the next divider.
func CardLines(messages []any, first string) []string {
	byID := map[string]O{}
	for _, m := range messages {
		mo, _ := m.(map[string]any)
		uc, _ := mo["updateComponents"].(map[string]any)
		comps, _ := uc["components"].([]any)
		for _, c := range comps {
			co, _ := c.(map[string]any)
			if id, ok := co["id"].(string); ok {
				if _, seen := byID[id]; !seen {
					byID[id] = co
				}
			}
		}
	}
	root := byID["root"]
	children, _ := root["children"].([]any)
	var order []O
	for _, ch := range children {
		if id, ok := ch.(string); ok && byID[id] != nil {
			order = append(order, byID[id])
		}
	}
	start := -1
	for i, c := range order {
		if c["component"] == "Text" && c["text"] == Clip(first) {
			start = i
			break
		}
	}
	if start < 0 {
		return nil
	}
	var out []string
	for _, c := range order[start:] {
		if c["component"] == "Divider" {
			break
		}
		if c["component"] == "Text" {
			if t, ok := c["text"].(string); ok {
				out = append(out, t)
			}
		}
	}
	return out
}

var _ = strings.TrimSpace

// Clone is a copy to add to without changing this one (Swift's Card is a value).
func (c *Card) Clone() *Card {
	d := *c
	d.components = append([]any(nil), c.components...)
	d.top = append([]string(nil), c.top...)
	d.choiceData = map[string]O{}
	for k, v := range c.choiceData {
		d.choiceData[k] = v
	}
	return &d
}
