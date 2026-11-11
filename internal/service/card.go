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
	asides     int  // numbered on their own, so adding an aside keeps every other id as it was
	inAside    bool // asides do not nest: an inner one adds its parts to the outer one
	groups     int  // collapsed groups, numbered on their own like asides
	features   map[string]bool
	layout     string // the root's layout: "sections" for a page drawn a card per part (§4 pageSections), or ""
	limit      int    // the most components it may have; 0: CardMaxComponents
	inPart     bool   // parts do not nest: an inner one adds its parts to the outer one
	parts      int    // parts, lists and items, numbered on their own like asides
}

// Use: the forms beyond version 1 that the agent core drawing this card knows (Features); none by default.
func (c *Card) Use(features map[string]bool) *Card {
	c.features = features
	return c
}

// Has: the core draws this form (§4 「后加的写法」).
func (c *Card) Has(feature string) bool { return c.features[feature] }

const (
	CardCatalog       = "ai.luoke/a2ui/agent/1"
	CardVersion       = "v0.9"
	CardMaxText       = 2000
	CardMaxComponents = 200
	PageMaxComponents = 400 // a page, where the core draws big pages (§4 bigPages)
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
	// Icon: an A2UI icon name (trash, check, folder) for an action that repeats card after card or that everyone
	// knows by its picture. The button's child is then a Row of the Icon and the label: next to other buttons the
	// window draws only the icon, the label as its tooltip and what a screen reader says (luoke-agent#60; 负责人
	// 11-07: too much repetition, make them icons). The label still says what happens.
	Icon string
	// Count: {"path": a group of choices, "value": one choice}, where the core draws counted labels (§4 countLabel):
	// {n} in the label becomes how many items of that group have that choice now, and at 0 the button is greyed.
	Count O
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

// Max is the most components it may have.
func (c *Card) Max() int {
	if c.limit > 0 {
		return c.limit
	}
	return CardMaxComponents
}

// Page makes it a tool's page for this core: up to PageMaxComponents where the core draws big pages (§4 bigPages), and
// a card per part where it draws pages that way (§4 pageSections; Part, List, Item, SectionCount).
func (c *Card) Page() *Card {
	if c.Has("bigPages") {
		c.limit = PageMaxComponents
	}
	if c.Has("pageSections") {
		c.layout = "sections"
	}
	return c
}

// Blank is an empty card drawn as this one is (its core's forms, its page's layout and size), to measure a part on.
func (c *Card) Blank() *Card {
	d := NewCard(c.SurfaceID, c.prefix).Use(c.features)
	d.layout, d.limit = c.layout, c.limit
	return d
}

// Sectioned: the page is drawn a card per part (Page, §4 pageSections).
func (c *Card) Sectioned() bool { return c.layout == "sections" }

// collect: the top-level components build adds, taken off the top level (to be wrapped).
func (c *Card) collect(build func()) A {
	before := len(c.top)
	build()
	kids := A{}
	for _, t := range c.top[before:] {
		kids = append(kids, t)
	}
	c.top = c.top[:before]
	return kids
}

// Part is one part of a page (「可以清掉」, 「要你看看」): what build adds, as one Column the core draws as a card of its
// own, its small title above the card (§4 pageSections). On a page not drawn that way, or inside another part, what
// build adds stays as it is.
func (c *Card) Part(build func()) {
	if !c.Sectioned() || c.inPart {
		build()
		return
	}
	c.inPart = true
	kids := c.collect(build)
	c.inPart = false
	if len(kids) == 0 {
		return
	}
	c.parts++
	c.add(O{"id": c.prefix + "part" + strconv.Itoa(c.parts), "component": "Column", "children": kids}, true)
}

// List: the items build adds (Item), as a List: a thin line between them (§4 List). On a page not drawn a card per part,
// as they are.
func (c *Card) List(build func()) {
	if !c.Sectioned() {
		build()
		return
	}
	kids := c.collect(build)
	if len(kids) == 0 {
		return
	}
	c.parts++
	c.add(O{"id": c.prefix + "list" + strconv.Itoa(c.parts), "component": "List", "children": kids}, true)
}

// Item: what build adds, as one item of a List (an item's row and the fold under it, one Column).
func (c *Card) Item(build func()) {
	if !c.Sectioned() {
		build()
		return
	}
	kids := c.collect(build)
	switch len(kids) {
	case 0:
	case 1:
		c.top = append(c.top, kids[0].(string))
	default:
		c.parts++
		c.add(O{"id": c.prefix + "item" + strconv.Itoa(c.parts), "component": "Column", "children": kids}, true)
	}
}

// SectionCount is a part's small title with its count (「要你看看」 「80」): where the page is drawn a card per part, the
// icon, the words and the number apart (§4 pageSections: the core draws the number lighter); else Section with the
// number after the words, as before.
func (c *Card) SectionCount(icon, text string, n int) {
	if !c.Sectioned() || !c.Has("lucide") || !LucideIcons[icon] {
		c.Section(icon, text+" "+strconv.Itoa(n))
		return
	}
	i, t, k := c.id("i"), c.id("t"), c.id("t")
	c.add(O{"id": i, "component": "Icon", "name": icon}, false)
	c.add(O{"id": t, "component": "Text", "text": Clip(text)}, false)
	c.add(O{"id": k, "component": "Text", "text": strconv.Itoa(n)}, false)
	c.add(O{"id": c.id("r"), "component": "Row", "children": A{i, t, k}}, true)
}

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

// PageHead is a page's first line: its title on the left, a note (when it last looked) and buttons on the right, in
// one Row (luoke-scan#129: 「扫描 · 上次查 11月9日 14:37 · 现在查一下」, the numbers under it). With nothing beside the
// title it is the Heading.
func (c *Card) PageHead(title, note string, buttons []Button) {
	h := c.id("h")
	c.add(O{"id": h, "component": "Text", "text": Clip(title), "variant": "h4"}, false)
	kids := A{h}
	if note != "" {
		n := c.id("n")
		c.add(O{"id": n, "component": "Text", "text": Clip(note), "variant": "caption"}, false)
		kids = append(kids, n)
	}
	for _, b := range buttons {
		kids = append(kids, c.button(b))
	}
	if len(kids) == 1 {
		c.top = append(c.top, h)
		return
	}
	c.add(O{"id": c.id("r"), "component": "Row", "justify": "spaceBetween", "children": kids}, true)
}

// fitLines: where the core cuts a text to a number of lines (§4 maxLines), one line for each line of the text, the
// rest of a line left out at its end (the core puts the whole text in the tooltip and gives it to a screen reader): an
// item's title and the lines under it, one line each as in the design (luoke-scan#129). keep: lines to read whole
// (sentences that say what to do), not cut.
func (c *Card) fitLines(comp O, keep bool) O {
	if keep || !c.Has("maxLines") {
		return comp
	}
	text, _ := comp["text"].(string)
	if n := strings.Count(text, "\n") + 1; n <= 20 { // §4: 1 to 20
		comp["maxLines"] = n
	}
	return comp
}

// itemText is an item's title or the lines under it (caption) on their own, as a core without item rows draws them.
func (c *Card) itemText(text string, caption, keep bool) {
	comp := O{"id": c.id("t"), "component": "Text", "text": Clip(text)}
	if caption {
		comp["variant"] = "caption"
	}
	c.add(c.fitLines(comp, keep), true)
}

// ItemLine is one line under an item's title (its names, what to do). Whole: sentences to read whole (steps to take
// at once), not cut to one line where the core cuts texts. Chips: the names apart, drawn as small blocks where the core
// draws them (§4 chips), More: 「等」 after them; Text is the line where it does not.
type ItemLine struct {
	Text  string
	Whole bool
	Chips []string
	More  bool
}

// itemLines: the lines under an item's title, as captions. Where the core cuts texts, a text for each line, each cut
// to one line (fitLines) unless whole: cut as one text, a long first line would push the next one out of sight
// (luoke-scan#153). Where it does not, the lines as one text, as before: each shows whole either way, and the page
// keeps its room. top: the texts go on the card on their own (a core without item rows), not into a column.
func (c *Card) itemLines(lines []ItemLine, top bool) A {
	lines = splitItemLines(lines)
	var kept []ItemLine
	for _, l := range lines {
		if len(l.Chips) > 0 && c.Has("chips") {
			l.Text = "" // drawn as chips below
			kept = append(kept, l)
		} else if l.Text != "" {
			l.Chips = nil
			kept = append(kept, l)
		}
	}
	if len(kept) > 1 && !c.Has("maxLines") && !hasChips(kept) {
		texts := make([]string, len(kept))
		for i, l := range kept {
			texts[i] = l.Text
		}
		kept = []ItemLine{{Text: strings.Join(texts, "\n")}}
	}
	var ids A
	for _, l := range kept {
		if len(l.Chips) > 0 {
			ids = append(ids, c.chips(l.Chips, l.More, top))
			continue
		}
		id := c.id("t")
		c.add(c.fitLines(O{"id": id, "component": "Text", "text": Clip(l.Text), "variant": "caption"}, l.Whole), top)
		ids = append(ids, id)
	}
	return ids
}

func hasChips(lines []ItemLine) bool {
	for _, l := range lines {
		if len(l.Chips) > 0 {
			return true
		}
	}
	return false
}

// chips: names as small blocks in one Row (§4 chips), beige where the core has neutral tags (§4 neutralBadge), 「等」
// after them when there are more; its id.
func (c *Card) chips(names []string, more, top bool) string {
	var kids A
	for _, n := range names {
		id := c.id("t")
		b := O{"id": id, "component": "Text", "text": Clip(n), "variant": "badge"}
		if c.Has("neutralBadge") {
			b["tone"] = "neutral"
		}
		c.add(b, false)
		kids = append(kids, id)
	}
	if more {
		id := c.id("t")
		c.add(O{"id": id, "component": "Text", "text": "等", "variant": "caption"}, false)
		kids = append(kids, id)
	}
	row := c.id("r")
	c.add(O{"id": row, "component": "Row", "children": kids}, top)
	return row
}

func (c *Card) Text(text string, caption ...bool) {
	comp := O{"id": c.id("t"), "component": "Text", "text": Clip(text)}
	if len(caption) > 0 && caption[0] {
		comp["variant"] = "caption"
	}
	c.add(comp, true)
}

func (c *Card) Divider() { c.add(O{"id": c.id("d"), "component": "Divider"}, true) }

// Aside wraps what build adds into one section the window may draw in its side column (tool protocol §4
// 「宽窗口的侧栏」): a Column right under the root with "placement": "aside". Narrow windows, and windows that do
// not know the property, draw it in place, so the order here is still the one-column order. Put a section's
// leading Divider inside build. Asides do not nest: one inside another just adds to the outer one.
func (c *Card) Aside(build func()) {
	if c.inAside {
		build()
		return
	}
	before := len(c.top)
	c.inAside = true
	build()
	c.inAside = false
	kids := A{}
	for _, t := range c.top[before:] {
		kids = append(kids, t)
	}
	c.top = c.top[:before]
	if len(kids) == 0 {
		return
	}
	c.asides++
	c.add(O{"id": c.prefix + "aside" + strconv.Itoa(c.asides), "component": "Column", "placement": "aside", "children": kids}, true)
}

// Option of a choice; Icon, drawn next to its words where the core draws option icons.
type Option struct{ Value, Label, Icon string }

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
	c.add(c.picker(key, label, options, g), true)
}

func (c *Card) picker(key, label string, options []Option, g string) O {
	opts := A{}
	for _, o := range options {
		opt := O{"label": o.Label, "value": o.Value}
		if o.Icon != "" && c.Has("optionIcons") && c.Has("lucide") && LucideIcons[o.Icon] {
			opt["icon"] = o.Icon
		}
		opts = append(opts, opt)
	}
	return O{"id": c.prefix + "c-" + key, "component": "ChoicePicker", "label": Clip(label), "options": opts,
		"value": O{"path": "/" + g + "/" + key}}
}

// Section is the small title of a part of a card or page (「可以清掉 3」): an icon and the words where the core draws
// Lucide icons, else a caption as before.
func (c *Card) Section(icon, text string) {
	if !c.Has("lucide") || !LucideIcons[icon] {
		c.Text(text, true)
		return
	}
	i, t := c.id("i"), c.id("t")
	c.add(O{"id": i, "component": "Icon", "name": icon}, false)
	c.add(O{"id": t, "component": "Text", "text": Clip(text)}, false)
	c.add(O{"id": c.id("r"), "component": "Row", "children": A{i, t}}, true)
}

// Collapsed wraps what build adds into a Column the window shows folded, one line (summary) with an arrow to open it,
// where the core draws that (§4 collapsed); else the summary is a caption and the rest follows it as before.
func (c *Card) Collapsed(summary string, build func()) {
	if !c.Has("collapsed") {
		c.Text(summary, true)
		build()
		return
	}
	before := len(c.top)
	build()
	kids := A{}
	for _, t := range c.top[before:] {
		kids = append(kids, t)
	}
	c.top = c.top[:before]
	if len(kids) == 0 {
		return
	}
	c.groups++
	c.add(O{"id": c.prefix + "fold" + strconv.Itoa(c.groups), "component": "Column", "collapsed": Clip(summary), "children": kids}, true)
}

// itemRows: the core draws an item as one row, its icon and words on the left, its choice or buttons on the right
// (§4 itemIcons, with the Lucide icons).
func (c *Card) itemRows() bool { return c.Has("itemIcons") && c.Has("lucide") }

// itemLeft: an item's icon, its title (with its size as a tag after it where the core draws tags) and the lines under
// it, the title one line and each line one line where the core cuts texts (fitLines, itemLines).
func (c *Card) itemLeft(icon, title, size string, lines []ItemLine) string {
	var head string
	if size != "" && c.Has("badge") {
		t, b := c.id("t"), c.id("t")
		c.add(c.fitLines(O{"id": t, "component": "Text", "text": Clip(title)}, false), false)
		c.add(O{"id": b, "component": "Text", "text": size, "variant": "badge"}, false)
		head = c.id("r")
		c.add(O{"id": head, "component": "Row", "children": A{t, b}}, false)
	} else {
		if size != "" {
			title += "（" + size + "）"
		}
		head = c.id("t")
		c.add(c.fitLines(O{"id": head, "component": "Text", "text": Clip(title)}, false), false)
	}
	col := append(A{head}, c.itemLines(lines, false)...)
	colID, iconID, left := c.id("c"), c.id("i"), c.id("r")
	c.add(O{"id": colID, "component": "Column", "children": col}, false)
	if !LucideIcons[icon] {
		icon = "file"
	}
	c.add(O{"id": iconID, "component": "Icon", "name": icon}, false)
	c.add(O{"id": left, "component": "Row", "children": A{iconID, colID}}, false)
	return left
}

// ItemChoice is one item with a choice of what to do: its icon, title, size and detail, the choice on the right; where
// the core does not draw item rows, the choice with the title (and size) as its label and the detail under it.
func (c *Card) ItemChoice(icon, title, size, detail, key string, options []Option, selected string) {
	if c.choiceData["choices"] == nil {
		c.choiceData["choices"] = O{}
	}
	c.choiceData["choices"][key] = A{selected}
	if !c.itemRows() {
		c.ItemChoiceShort(title, size, detail, key, options, selected)
		return
	}
	label := title
	if size != "" {
		label += "（" + size + "）"
	}
	left := c.itemLeft(icon, title, size, []ItemLine{{Text: detail}})
	p := c.picker(key, label, options, "choices")
	c.add(p, false)
	c.add(O{"id": c.id("r"), "component": "Row", "justify": "spaceBetween", "children": A{left, p["id"]}}, true)
}

// ItemChoiceShort is ItemChoice in two components (the choice with the title as its label, the detail under it), as a
// core without item rows draws it: for a page that has no room left for the nine of an item row.
func (c *Card) ItemChoiceShort(title, size, detail, key string, options []Option, selected string) {
	if c.choiceData["choices"] == nil {
		c.choiceData["choices"] = O{}
	}
	c.choiceData["choices"][key] = A{selected}
	if size != "" {
		title += "（" + size + "）"
	}
	c.add(c.picker(key, title, options, "choices"), true)
	if detail != "" {
		c.itemText(detail, true, false)
	}
}

// Fits: what build adds, drawn on a copy, leaves room for after more components within the card's 200.
func (c *Card) Fits(after int, build func(*Card)) bool {
	d := c.Clone()
	build(d)
	return d.Count()+after <= c.Max()
}

// ItemButtons is one item with buttons: its icon, title and the lines under it, the buttons on the right; where the
// core does not draw item rows, the title, the lines as captions, then the buttons.
func (c *Card) ItemButtons(icon, title string, lines []ItemLine, buttons []Button) {
	if !c.itemRows() {
		c.itemText(title, false, false)
		c.itemLines(lines, true)
		if len(buttons) > 0 {
			c.Buttons(buttons)
		}
		return
	}
	left := c.itemLeft(icon, title, "", lines)
	kids := A{left}
	if len(buttons) > 0 {
		before := len(c.top)
		c.Buttons(buttons)
		row := c.top[before]
		c.top = c.top[:before]
		kids = append(kids, row)
	}
	c.add(O{"id": c.id("r"), "component": "Row", "justify": "spaceBetween", "children": kids}, true)
}

// Defaults puts a choice's value in the data model without drawing it: a button that applies a plan as suggested
// (「清理」) without listing every item on the card. The items and their choices are on the tool's page.
func (c *Card) Defaults(key, selected string, group ...string) {
	g := "choices"
	if len(group) > 0 {
		g = group[0]
	}
	if c.choiceData[g] == nil {
		c.choiceData[g] = O{}
	}
	c.choiceData[g][key] = A{selected}
}

// Stat is one number on a page: what it counts, and the number.
type Stat struct{ Key, Value string }

// Stats is a row of numbers, each a caption over a large figure (the page's top, as in the prototype).
func (c *Card) Stats(stats []Stat) {
	var cols []any
	for _, st := range stats {
		col := c.id("s")
		k, v := c.id("t"), c.id("t")
		c.add(O{"id": k, "component": "Text", "text": Clip(st.Key), "variant": "caption"}, false)
		c.add(O{"id": v, "component": "Text", "text": Clip(st.Value), "variant": "h3"}, false)
		c.add(O{"id": col, "component": "Column", "children": A{k, v}}, false)
		cols = append(cols, col)
	}
	if cols == nil {
		return
	}
	// spaceEvenly: the numbers equally wide, each from the left (with spaceBetween the window put the first on the left and
	// the rest together on the right; design review luoke-scan#124 r1)
	c.add(O{"id": c.id("r"), "component": "Row", "children": cols, "justify": "spaceEvenly"}, true)
}

// Line is one row of a list to look at: what it is on the left, its value on the right (a caption), then a progress
// bar at the far right when progress is 0 to 1 (below 0: none). The same row the search page draws (its Cards.line).
func (c *Card) Line(label, value string, progress float64) { c.line(label, value, progress, nil) }

// StateLine is a Line whose value ends with an icon for its state (a check, a warning, a question mark): the states
// differ in shape, not only in words.
func (c *Card) StateLine(label, icon, state string, alert bool) {
	k, i, v := c.id("t"), c.id("i"), c.id("t")
	c.add(O{"id": k, "component": "Text", "text": Clip(label)}, false)
	c.add(O{"id": i, "component": "Icon", "name": c.iconName(icon)}, false)
	value := O{"id": v, "component": "Text", "text": Clip(state)}
	if !alert {
		value["variant"] = "caption" // 没问题的灰一档；有问题的用正文的深色，一眼看得到（设计评审 r3）
	}
	c.add(value, false)
	// 图标在最右边：几行的图标排成一列，不跟着前面的字宽错开（设计评审 r4）
	c.add(O{"id": c.id("r"), "component": "Row", "children": A{k, v, i}, "justify": "spaceBetween"}, true)
}

// LineButtons is Line with buttons after the value in the same row (「在访达里显示」, 「打开设置」).
func (c *Card) LineButtons(label, value string, buttons []Button) { c.line(label, value, -1, buttons) }

func (c *Card) line(label, value string, progress float64, buttons []Button) {
	k := c.id("t")
	c.add(O{"id": k, "component": "Text", "text": Clip(label)}, false)
	children := A{k}
	if value != "" {
		v := c.id("t")
		c.add(O{"id": v, "component": "Text", "text": Clip(value), "variant": "caption"}, false)
		children = append(children, v)
	}
	if progress >= 0 { // 条在最右边：一样宽，几行的条排成一列，不跟着前面的字长短错开（设计评审 r2 前自查）
		p := c.id("p")
		if progress > 1 {
			progress = 1
		}
		c.add(O{"id": p, "component": "ProgressBar", "value": progress}, false)
		children = append(children, p)
	}
	for _, b := range buttons {
		children = append(children, c.button(b))
	}
	c.add(O{"id": c.id("r"), "component": "Row", "children": children, "justify": "spaceBetween"}, true)
}

func (c *Card) Buttons(specs []Button) { c.ButtonsAfter("", specs) }

// ButtonsAfter: a row of buttons with a short note in front of it in the same row (「另外 1 项照建议处理」 before
// 「按上面的选择清理」): what the button also does, said where the button is.
func (c *Card) ButtonsAfter(note string, specs []Button) {
	var ids []any
	if note != "" {
		nid := c.id("n")
		c.add(O{"id": nid, "component": "Text", "text": note, "variant": "caption"}, false)
		ids = append(ids, nid)
	}
	for _, b := range specs {
		ids = append(ids, c.button(b))
	}
	if ids == nil {
		ids = A{}
	}
	c.add(O{"id": c.id("r"), "component": "Row", "children": ids}, true)
}

// Switch is a setting turned on or off: what it is on the left, the switch on the right (tool protocol: a Button with
// variant switch and on; the switch draws no words, its label is what a screen reader says). label says what a click
// does (「打开自动清理」), so a core that draws it as a button still reads right.
func (c *Card) Switch(text, label string, on bool, event string, context O) {
	t, b := c.id("t"), c.id("b")
	c.add(O{"id": t, "component": "Text", "text": Clip(text)}, false)
	c.add(O{"id": b, "component": "Button", "variant": "switch", "on": on, "child": b + "-text",
		"action": O{"event": O{"name": event, "context": context}}}, false)
	c.add(O{"id": b + "-text", "component": "Text", "text": Clip(label)}, false)
	c.add(O{"id": c.id("r"), "component": "Row", "justify": "spaceBetween", "children": A{t, b}}, true)
}

func (c *Card) body() A {
	top := A{}
	for _, t := range c.top {
		top = append(top, t)
	}
	root := O{"id": "root", "component": "Column", "children": top}
	if c.layout != "" {
		root["layout"] = c.layout
	}
	return append(A{root}, c.components...)
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
		id, _ := ch.(string)
		c := byID[id]
		if c == nil {
			continue
		}
		if c["component"] == "Column" && c["placement"] == "aside" { // read an aside in place, as one column
			kids, _ := c["children"].([]any)
			for _, k := range kids {
				if kid, ok := k.(string); ok && byID[kid] != nil {
					order = append(order, byID[kid])
				}
			}
			continue
		}
		order = append(order, c)
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
		d.choiceData[k] = O{}
		for kk, vv := range v {
			d.choiceData[k][kk] = vv
		}
	}
	return &d
}

// button adds one button (not at the top level) and returns its id.
// iconName: a version 1 icon name, as Lucide names it when the host has Lucide (旧名字照旧认，§4).
func (c *Card) iconName(icon string) string {
	if n, ok := lucideNames[icon]; ok && c.Has("lucide") {
		return n
	}
	return icon
}

func (c *Card) button(b Button) string {
	bid := c.id("b")
	tid := bid + "-text"
	ctx := b.Context
	if ctx == nil {
		ctx = O{}
	}
	child := tid
	if b.Icon != "" {
		child = bid + "-row"
	}
	comp := O{"id": bid, "component": "Button", "child": child, "action": O{"event": O{"name": b.Event, "context": ctx}}}
	if b.Primary {
		comp["variant"] = "primary"
	}
	if b.Count != nil {
		comp["count"] = b.Count
	}
	c.add(comp, false)
	if child != tid {
		c.add(O{"id": child, "component": "Row", "children": A{bid + "-icon", tid}}, false)
		c.add(O{"id": bid + "-icon", "component": "Icon", "name": c.iconName(b.Icon)}, false)
	}
	c.add(O{"id": tid, "component": "Text", "text": b.Label}, false)
	return bid
}

// splitItemLines: a line of several (an item's detail, an advice with what to do on a line of its own) as a line each,
// so where the core cuts texts each is cut on its own: a long first line does not push the next one, often what to
// do, out of sight. Sentences read whole stay one text (they are not cut).
func splitItemLines(lines []ItemLine) []ItemLine {
	var out []ItemLine
	for _, l := range lines {
		if l.Whole || !strings.Contains(l.Text, "\n") {
			out = append(out, l)
			continue
		}
		for _, t := range strings.Split(l.Text, "\n") {
			out = append(out, ItemLine{Text: t, Whole: l.Whole})
		}
	}
	return out
}
