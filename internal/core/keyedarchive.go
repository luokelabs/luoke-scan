package core

import "strings"

// An NSKeyedArchiver archive read as data (a decoded property list): $objects, and what the UIDs in it point at.
// Nothing is instantiated; a class is only its name. Used for the background items macOS keeps (backgrounditems.go).

type keyedArchive struct{ objects []any }

// readKeyedArchive is the archive in a decoded property list and its $top; ok false when it is not one.
func readKeyedArchive(v any) (keyedArchive, map[string]any, bool) {
	d, ok := v.(map[string]any)
	if !ok {
		return keyedArchive{}, nil, false
	}
	if a, _ := d["$archiver"].(string); a != "NSKeyedArchiver" {
		return keyedArchive{}, nil, false
	}
	objects, ok1 := d["$objects"].([]any)
	top, ok2 := d["$top"].(map[string]any)
	if !ok1 || !ok2 {
		return keyedArchive{}, nil, false
	}
	return keyedArchive{objects}, top, true
}

// archiveUID is the index a UID holds: binary (PlistUID), or as XML writes it ({"CF$UID": n}).
func archiveUID(v any) (uint64, bool) {
	switch x := v.(type) {
	case PlistUID:
		return uint64(x), true
	case map[string]any:
		if n, ok := x["CF$UID"].(int64); ok && len(x) == 1 && n >= 0 {
			return uint64(n), true
		}
	}
	return 0, false
}

// at is what v stands for: the object a UID points at (nil for "$null" and for one out of range), else v itself.
func (a keyedArchive) at(v any) any {
	i, ok := archiveUID(v)
	if !ok {
		return v
	}
	if i >= uint64(len(a.objects)) {
		return nil
	}
	o := a.objects[i]
	if s, ok := o.(string); ok && s == "$null" {
		return nil
	}
	return o
}

// object is v as an archived object (a dictionary); ok false for anything else.
func (a keyedArchive) object(v any) (map[string]any, bool) {
	o, ok := a.at(v).(map[string]any)
	return o, ok
}

// str is a string: one written as is, or an NSString object (NS.string).
func (a keyedArchive) str(v any) string {
	switch x := a.at(v).(type) {
	case string:
		return x
	case map[string]any:
		if s, ok := a.at(x["NS.string"]).(string); ok {
			return s
		}
	}
	return ""
}

// num is an integer; ok false for anything else.
func (a keyedArchive) num(v any) (int64, bool) {
	n, ok := a.at(v).(int64)
	return n, ok
}

// list is what an NSArray or NSSet holds (NS.objects), each one looked up; ok false when v is not one.
func (a keyedArchive) list(v any) ([]any, bool) {
	o, ok := a.object(v)
	if !ok {
		return nil, false
	}
	refs, ok := o["NS.objects"].([]any)
	if !ok {
		return nil, false
	}
	out := make([]any, 0, len(refs))
	for _, r := range refs {
		out = append(out, a.at(r))
	}
	return out, true
}

// strings is a list of strings (an NSArray or NSSet of them, or one string); what is not a string is left out.
func (a keyedArchive) strings(v any) []string {
	if s := a.str(v); s != "" {
		return []string{s}
	}
	l, _ := a.list(v)
	var out []string
	for _, x := range l {
		if s := a.str(x); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// dict is an NSDictionary (NS.keys, NS.objects) with string keys, the values looked up; ok false when v is not one.
func (a keyedArchive) dict(v any) (map[string]any, bool) {
	o, ok := a.object(v)
	if !ok {
		return nil, false
	}
	keys, ok1 := o["NS.keys"].([]any)
	values, ok2 := o["NS.objects"].([]any)
	if !ok1 || !ok2 || len(keys) != len(values) {
		return nil, false
	}
	out := make(map[string]any, len(keys))
	for i, k := range keys {
		if s := a.str(k); s != "" {
			out[s] = a.at(values[i])
		}
	}
	return out, true
}

// url is an NSURL's address: NS.relative, put after NS.base when there is one (a few levels at most).
func (a keyedArchive) url(v any) string {
	for depth, rel := 0, ""; depth < 4; depth++ {
		o, ok := a.object(v)
		if !ok {
			return rel
		}
		r := a.str(o["NS.relative"])
		if rel == "" {
			rel = r
		} else if r != "" {
			rel = strings.TrimSuffix(r, "/") + "/" + strings.TrimPrefix(rel, "/")
		}
		if o["NS.base"] == nil || a.at(o["NS.base"]) == nil {
			return rel
		}
		v = o["NS.base"]
	}
	return ""
}
