package service

import (
	"reflect"
	"testing"
)

// Aside: a Column right under the root with "placement": "aside", in the one-column order (tool protocol §4
// 「宽窗口的侧栏」); an empty one adds nothing; CardLines reads through it.
func TestAsideWrapsSectionsInPlace(t *testing.T) {
	c := NewCard("p")
	c.Heading("扫描")
	c.Aside(func() {
		c.Text("上一轮 10月20日 20:00", true)
		c.Buttons([]Button{{Label: "现在查一下", Event: "scan_now"}})
	})
	c.Text("要你看看的")
	c.Aside(func() {})
	c.Aside(func() { c.Aside(func() { c.Text("里面那层", true) }) })
	c.Aside(func() {
		c.Divider()
		c.Text("自动清理：关", true)
	})

	body := c.body()
	byID := map[string]O{}
	for _, x := range body[1:] {
		o := x.(O)
		byID[o["id"].(string)] = o
	}
	kids := body[0].(O)["children"].(A)
	var kinds []string
	for _, k := range kids {
		comp := byID[k.(string)]
		kind := comp["component"].(string)
		if comp["placement"] != nil {
			kind += ":" + comp["placement"].(string)
		}
		kinds = append(kinds, kind)
	}
	if want := []string{"Text", "Column:aside", "Text", "Column:aside", "Column:aside"}; !reflect.DeepEqual(kinds, want) {
		t.Fatalf("root children %v, want %v", kinds, want)
	}
	first := byID[kids[1].(string)]["children"].(A)
	if len(first) != 2 || byID[first[0].(string)]["text"] != "上一轮 10月20日 20:00" || byID[first[1].(string)]["component"] != "Row" {
		t.Fatalf("first aside holds %v", first)
	}
	nested := byID[kids[3].(string)]["children"].(A)
	if len(nested) != 1 || byID[nested[0].(string)]["text"] != "里面那层" {
		t.Fatalf("an aside inside an aside adds to the outer one: %v", nested)
	}
	last := byID[kids[4].(string)]["children"].(A)
	if byID[last[0].(string)]["component"] != "Divider" {
		t.Fatalf("the last aside starts with its divider: %v", last)
	}
	if c.Count() != len(body) {
		t.Fatalf("Count %d, components %d", c.Count(), len(body))
	}

	if got, want := CardLines(c.Messages(), "上一轮 10月20日 20:00"), []string{"上一轮 10月20日 20:00", "要你看看的", "里面那层"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CardLines %v, want %v", got, want)
	}
	if got, want := CardLines(c.Messages(), "自动清理：关"), []string{"自动清理：关"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CardLines %v, want %v", got, want)
	}
}
