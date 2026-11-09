package service

import (
	"io/fs"
	"os"
	"reflect"
	"testing"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// The packed build's prompts are the ones inside the program: the same files as prompts/, read the same way.
func TestCarriedPromptsAreTheRepositorys(t *testing.T) {
	carried, ok := Prompts(true)
	if !ok {
		t.Fatal("no prompts inside the program")
	}
	disk := os.DirFS("../../prompts")
	names := func(fsys fs.FS) []string {
		es, _ := fs.ReadDir(fsys, ".")
		var out []string
		for _, e := range es {
			out = append(out, e.Name())
		}
		return out
	}
	if a, b := names(carried), names(disk); !reflect.DeepEqual(a, b) || len(a) == 0 {
		t.Fatalf("carried %v, prompts/ %v", a, b)
	}
	for _, task := range []string{"explain", "identify", "skills"} {
		a, err := core.LoadPromptFS(task, carried)
		if err != nil {
			t.Fatal(err)
		}
		b, err := core.LoadPrompt(task, "../../prompts")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: carried prompt differs from prompts/", task)
		}
	}
}
