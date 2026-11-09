// luoke-scan-admin is the password step: what 螺壳 starts with administrator rights (after the user's password) to
// move an app's data out of the system's Library, or an old Intel Homebrew out of /usr/local (service.AdminApply). It
// only ever runs as root after root checked this program's signature. It takes no folder: it finds the user's plan
// from the user id, and judges every item again before moving it.
package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/luokelabs/luoke-scan/internal/service"
)

const usage = "用法：luoke-scan-admin --plan <编号> --user <uid> --keys <项,…> --apps <bundle id,…> [--homebrew]（只由螺壳扫描经 macOS 的密码框起）"

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(64)
}

var (
	keyRE = regexp.MustCompile(`^a[0-9]{1,3}$`)
	appRE = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+){2,}$`)
)

func main() {
	service.CloseInherited()
	args := os.Args[1:]
	homebrew := false // the user's process judged the Intel Homebrew again and asks for it
	var rest []string
	for _, a := range args {
		if a == "--homebrew" {
			homebrew = true
		} else {
			rest = append(rest, a)
		}
	}
	values := map[string]string{}
	for len(rest) >= 2 && strings.HasPrefix(rest[0], "--") {
		if _, seen := values[rest[0]]; seen {
			fail(usage)
		}
		values[rest[0]] = rest[1]
		rest = rest[2:]
	}
	plan, okPlan := values["--plan"]
	uidText, okUID := values["--user"]
	keys, okKeys := values["--keys"]
	apps, okApps := values["--apps"]
	if !okPlan || !okUID || !okKeys || !okApps || len(rest) > 0 || len(values) != 4 {
		fail(usage)
	}
	uid, err := strconv.ParseUint(uidText, 10, 32)
	if err != nil {
		fail(usage)
	}
	var list []string
	for _, k := range strings.Split(keys, ",") {
		if k != "" {
			list = append(list, k)
		}
	}
	if len(list) == 0 {
		fail("--keys 不对")
	}
	for _, k := range list {
		if !keyRE.MatchString(k) {
			fail("--keys 不对")
		}
	}
	var ids []string
	for _, a := range strings.Split(apps, ",") {
		if a != "" {
			ids = append(ids, a)
		}
	}
	// No apps when only the Intel Homebrew goes.
	if len(ids) == 0 && !homebrew {
		fail("--apps 不对")
	}
	for _, a := range ids {
		if !appRE.MatchString(a) {
			fail("--apps 不对")
		}
	}
	os.Exit(service.RunAdmin(plan, uint32(uid), list, ids, homebrew))
}
