package service

import (
	"encoding/json"
	"os"
	"testing"
)

// The version is in two places that must agree: the accessory manifest and ToolVersion.
func TestVersionMatchesManifest(t *testing.T) {
	data, err := os.ReadFile("../../packaging/luoke-accessory.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct{ Version string }
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != ToolVersion {
		t.Fatalf("manifest %s, ToolVersion %s", m.Version, ToolVersion)
	}
}

// capabilities.permissions is the one place that declares a permission; a job only names what it uses.
func TestManifestDeclaresPermissionsOnce(t *testing.T) {
	data, err := os.ReadFile("../../packaging/luoke-accessory.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"resident_exec", "resident_command", "resident_permissions"} {
		if _, ok := m[key]; ok {
			t.Errorf("%s is still there", key)
		}
	}
	declared := map[string]bool{}
	for _, p := range m["capabilities"].(map[string]any)["permissions"].([]any) {
		declared[p.(map[string]any)["id"].(string)] = true
	}
	uses := map[string][]any{}
	for _, j := range m["jobs"].([]any) {
		job := j.(map[string]any)
		if _, ok := job["permissions"]; ok {
			t.Errorf("job %v still has permissions", job["name"])
		}
		if u, ok := job["uses"].([]any); ok {
			uses[job["name"].(string)] = u
			for _, id := range u {
				if !declared[id.(string)] {
					t.Errorf("job %v uses %v, not declared", job["name"], id)
				}
			}
		}
	}
	if len(uses) != 1 || len(uses["scan"]) != 1 || uses["scan"][0] != "fda" {
		t.Fatalf("uses: %v", uses)
	}
}
