package main

import (
	"os"

	"github.com/luokelabs/luoke-scan/internal/core"
)

// fixtureOnlyFlag is set when building the copy for a development instance of 螺壳 (scripts/package_app.py
// --fixture-only: -ldflags "-X main.fixtureOnlyFlag=1"). That copy looks only at a fake Mac made by
// scripts/make_fixture.py: never this Mac, never another program or folder given on the command line.
var fixtureOnlyFlag = ""

func fixtureOnly() bool { return fixtureOnlyFlag == "1" }

// fixtureOnlyWord names the fixture-only copy in its version line and in every refusal (scripts/package_app.py looks
// for it in both).
const fixtureOnlyWord = "只查假 Mac 的开发构建"

// fixtureOnlyCommands are what the fixture-only copy runs: the ones that look at or change a fake Mac (they go through
// setup, which takes only --fixture there), and the ones that read a data directory given by hand.
var fixtureOnlyCommands = map[string]bool{"version": true, "scan": true, "mcp": true, "system": true, "cleaned": true,
	"restore": true, "report": true, "findings": true, "status": true}

// fixtureOnlyRefusal is why the fixture-only copy will not run command with args, "" when it will. Flags that point at
// this Mac, its folders or other programs are refused wherever they stand; so is every command that updates the
// virus database, imports a list or runs an eval.
func fixtureOnlyRefusal(command string, args []string) string {
	if core.Packed() {
		return "这份 luoke-scan 编错了：装进螺壳的标记和" + fixtureOnlyWord + "的标记只能有一个"
	}
	for _, a := range args {
		switch a {
		case "--this-mac", "--home", "--tmp", "--projects", "--tool-dir":
			return a + " 不给" + fixtureOnlyWord + "用：它只查 --fixture 给的假 Mac（scripts/make_fixture.py 造的）"
		}
	}
	if !fixtureOnlyCommands[command] {
		return command + " 不给" + fixtureOnlyWord + "用"
	}
	return ""
}

// fakeMacProblem is why root is not a fake Mac the fixture-only copy may look at and clean, "" when it is: its home is
// a folder of its own (not a link, not this Mac's home), and fakes.json stands in for this Mac's processes and
// settings (without it a fake home is looked at with some of this Mac's state).
func fakeMacProblem(l core.Layout, haveFakes bool, realHome string) string {
	fi, err := os.Lstat(l.Home())
	if err != nil || !fi.IsDir() {
		return l.Root + " 不是假 Mac：home 要是它自己的文件夹，不能是链接（假 Mac 由 scripts/make_fixture.py 造）"
	}
	if h, err := os.Stat(realHome); err == nil && os.SameFile(fi, h) {
		return l.Root + " 不是假 Mac：home 就是这台 Mac 的家目录"
	}
	if !haveFakes {
		return l.Root + " 不是假 Mac：没有 fakes.json（假 Mac 由 scripts/make_fixture.py 造）"
	}
	return ""
}
