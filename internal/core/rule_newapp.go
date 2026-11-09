package core

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// NewAppRule: apps that came into /Applications or ~/Applications in the last month, checked as Gatekeeper would on
// first launch: signed, the signature intact, and notarized by Apple (or from the App Store, or Apple's own). Where
// one came from is read from its quarantine record. Nothing is opened, run or sent anywhere. The web apps a browser
// makes of pages are signed ad hoc by the browser itself and left out (isWebApp). Swift: Rules/NewAppRule.swift.
type NewAppRule struct {
	Recent time.Duration
	// Trust is what vouches for an app.
	Trust func(app string) AppTrust
	// Added is when the app came into its folder, else when it was made; ok false when not known.
	Added func(app string) (time.Time, bool)
	// DownloadedBy is the program that downloaded it ("" when its quarantine record names none); ok false when it has none.
	DownloadedBy func(app string) (string, bool)
}

// TrustKind is who vouches for an app.
type TrustKind int

const (
	TrustApple TrustKind = iota
	TrustAppStore
	TrustNotarized
	TrustDeveloper // a developer's signature that Apple has not notarized
	TrustAdhoc
	TrustUnsigned
	TrustInvalid // signed, but the signature no longer matches the program
)

// AppTrust is what vouches for an app, with the developer's Team ID.
type AppTrust struct {
	Kind TrustKind `json:"kind"`
	Team string    `json:"team,omitempty"`
}

// ParseAppTrust reads the fakes' spelling: apple, appStore, notarized, developer:<team>, adhoc, invalid; else unsigned.
func ParseAppTrust(s string) AppTrust {
	switch s {
	case "apple":
		return AppTrust{Kind: TrustApple}
	case "appStore":
		return AppTrust{Kind: TrustAppStore}
	case "notarized":
		return AppTrust{Kind: TrustNotarized}
	case "adhoc":
		return AppTrust{Kind: TrustAdhoc}
	case "invalid":
		return AppTrust{Kind: TrustInvalid}
	}
	if strings.HasPrefix(s, "developer:") {
		return AppTrust{Kind: TrustDeveloper, Team: strings.TrimPrefix(s, "developer:")}
	}
	return AppTrust{Kind: TrustUnsigned}
}

func init() { Register("apps.new", NewNewAppRule) }

// NewNewAppRule is the rule for this Mac (l nil) or a fake home: there when each app came is the fakes' appsAdded, and
// what vouches for the apps in appTrust is from there (the others are asked of codesign).
func NewNewAppRule(l *Layout, f *Fakes) Rule {
	r := &NewAppRule{Recent: 30 * 24 * time.Hour, Trust: AppTrustOf, Added: DateAdded, DownloadedBy: QuarantineAgent}
	if l != nil {
		r.Added = func(app string) (time.Time, bool) {
			t, ok := f.AppsAdded[app]
			return t, ok
		}
		r.Trust = func(app string) AppTrust {
			if s, ok := f.AppTrust[app]; ok {
				return ParseAppTrust(s)
			}
			return AppTrustOf(app)
		}
	}
	return r
}

func (r *NewAppRule) ID() string { return "apps.new" }
func (r *NewAppRule) Emits() []string {
	return []string{"apps.bad-signature", "apps.unsigned", "apps.not-notarized"}
}

// AppTrustOf checks an app's main program and signature with codesign and the requirements Gatekeeper cares about,
// offline and without hashing the bundle's resources: notarization is known from a stapled ticket or one this Mac
// already has. Who signed it is read first (codesign -d hashes nothing) and only that certificate's requirement is
// checked: two codesign runs and one pass over the program instead of up to five; anything not recognised is checked
// the long way (appTrustSlow).
func AppTrustOf(app string) AppTrust {
	shown := showSignature(app)
	switch {
	case shown.notSigned || (!shown.ok && !Exists(app)):
		return AppTrust{Kind: TrustUnsigned}
	case !shown.ok:
		return appTrustSlow(app)
	case shown.adhoc || shown.adhocDir:
		if verifySignature(app, "") != 0 {
			return AppTrust{Kind: TrustInvalid}
		}
		return AppTrust{Kind: TrustAdhoc}
	}
	requirement, kind := "anchor apple", TrustApple
	switch {
	case shown.leaf == leafAppStore:
		requirement, kind = appStoreRequirement, TrustAppStore
	case strings.HasPrefix(shown.leaf, leafDeveloperID):
		requirement, kind = "notarized", TrustNotarized
	}
	switch verifySignature(app, requirement) {
	case 0:
		return AppTrust{Kind: kind}
	case codesignUnmet:
		if kind != TrustNotarized {
			return appTrustSlow(app) // intact, but not Apple's or the App Store's: the long way tells
		}
		if s := shown.developerOrAdhoc(); s.Kind == SigDeveloper {
			return AppTrust{Kind: TrustDeveloper, Team: s.Team}
		}
		return AppTrust{Kind: TrustAdhoc}
	case -1:
		return appTrustSlow(app) // codesign did not finish: one requirement at a time, as before
	}
	return AppTrust{Kind: TrustInvalid}
}

// appStoreRequirement: signed by the App Store (Apple's Mac App Store certificate).
const appStoreRequirement = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists"

// appTrustSlow checks one requirement at a time: intact, Apple's, the App Store's, notarized, then who signed it.
func appTrustSlow(app string) AppTrust {
	verify := func(extra ...string) ProcResult {
		args := append([]string{"--verify", "--no-strict", "--ignore-resources"}, extra...)
		return Run(codesign, append(args, app), RunOpts{Timeout: 60 * time.Second})
	}
	if v := verify(); v.Status != 0 {
		if strings.Contains(v.Stderr, "not signed at all") || !Exists(app) {
			return AppTrust{Kind: TrustUnsigned}
		}
		return AppTrust{Kind: TrustInvalid}
	}
	if verify("-R=anchor apple").Status == 0 {
		return AppTrust{Kind: TrustApple}
	}
	if verify("-R="+appStoreRequirement).Status == 0 {
		return AppTrust{Kind: TrustAppStore}
	}
	if verify("-R=notarized").Status == 0 {
		return AppTrust{Kind: TrustNotarized}
	}
	d := Run(codesign, []string{"-dvv", app}, RunOpts{Timeout: 60 * time.Second})
	team := ""
	for _, line := range strings.Split(d.Stdout+d.Stderr, "\n") {
		if line == "Signature=adhoc" || (strings.HasPrefix(line, "CodeDirectory ") && strings.Contains(line, "flags=0x2(adhoc)")) {
			return AppTrust{Kind: TrustAdhoc}
		}
		if strings.HasPrefix(line, "TeamIdentifier=") {
			team = strings.TrimPrefix(line, "TeamIdentifier=")
		}
	}
	if team != "" && team != "not set" {
		return AppTrust{Kind: TrustDeveloper, Team: team}
	}
	return AppTrust{Kind: TrustAdhoc}
}

// webAppBrowsers are the data folders of the Chromium browsers (as the browser rule knows them), under the home.
var webAppBrowsers = []string{"Library/Application Support/Google/Chrome", "Library/Application Support/Google/Chrome Beta",
	"Library/Application Support/Microsoft Edge", "Library/Application Support/BraveSoftware/Brave-Browser",
	"Library/Application Support/Arc/User Data", "Library/Application Support/Vivaldi", "Library/Application Support/Chromium"}

// isWebApp: a web app a Chromium browser made of a page ("Install as app"): a small launcher the browser writes into
// `<browser> Apps.localized` in an Applications folder and signs itself, ad hoc by design. Known by where it is, what
// the browser writes in its Info.plist, and the browser's own record of that web app in a known browser's data folder.
func isWebApp(app, home string, appDirs []string) bool {
	folder := filepath.Dir(app)
	if !strings.HasSuffix(filepath.Base(folder), " Apps.localized") {
		return false
	}
	inAppDir := false
	for _, d := range appDirs {
		inAppDir = inAppDir || Standardized(d) == Standardized(filepath.Dir(folder))
	}
	if !inAppDir {
		return false
	}
	p, ok := readJobPlist(filepath.Join(app, "Contents/Info.plist"))
	if !ok || PlistString(p, "CFBundleExecutable") != "app_mode_loader" {
		return false
	}
	id, _ := p["CrAppModeShortcutID"].(string)
	if len([]rune(id)) != 32 {
		return false
	}
	for _, c := range id {
		if c < 'a' || c > 'p' {
			return false
		}
	}
	browser, _ := p["CrBundleIdentifier"].(string)
	bundle, _ := p["CFBundleIdentifier"].(string)
	data, hasData := p["CrAppModeUserDataDir"].(string)
	if browser == "" || !strings.HasPrefix(bundle, browser+".app.") || !strings.HasSuffix(bundle, id) || !hasData {
		return false
	}
	// <the browser's data folder>/<profile>/Web Applications/_crx_<id>, the data folder one of the browsers this home has.
	crx := Standardized(data)
	if filepath.Base(crx) != "_crx_"+id || filepath.Base(filepath.Dir(crx)) != "Web Applications" {
		return false
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(crx)))
	known := false
	for _, b := range webAppBrowsers {
		known = known || Standardized(filepath.Join(home, b)) == root
	}
	if !known {
		return false
	}
	if Exists(crx) {
		return true
	}
	for _, prof := range Children(root) {
		if Exists(filepath.Join(prof, "Web Applications/Manifest Resources", id)) {
			return true
		}
	}
	return false
}

// newAppCandidates are the apps in dirs (and one folder down: /Applications/Utilities, a vendor's folder), not /System's.
func newAppCandidates(dirs []string) []string {
	var out []string
	for _, d := range dirs {
		if strings.HasPrefix(d, "/System/") {
			continue
		}
		for _, u := range Children(d) {
			if PathExtension(u) == "app" {
				out = append(out, u)
				continue
			}
			for _, c := range Children(u) {
				if PathExtension(c) == "app" {
					out = append(out, c)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

type keptTrust struct {
	Identity string    `json:"identity"`
	Trust    AppTrust  `json:"trust"`
	At       time.Time `json:"at"`
}

func (r *NewAppRule) Run(ctx *Context) ([]Finding, error) {
	var out []Finding
	// What an app was found to be is kept while it is the same (SignatureIdentity: its main program, Info.plist and
	// signature record), for a week at most: an app stays "recent" for a month and is not checked every round.
	known := map[string]keptTrust{}
	if ctx.Store != nil {
		if v, ok := ctx.Store.Get("apps.trust"); ok {
			json.Unmarshal([]byte(v), &known)
		}
	}
	kept := map[string]keptTrust{}
	defer func() {
		if ctx.Store != nil {
			if data, err := json.Marshal(kept); err == nil {
				ctx.Store.Set("apps.trust", string(data))
			}
		}
	}()
	for _, app := range newAppCandidates(ctx.AppDirs) {
		if ctx.IsCancelled() {
			return nil, Skip(Interrupted, out...)
		}
		came, ok := r.Added(app)
		if !ok || ctx.Now.Sub(came) >= r.Recent {
			continue
		}
		id := SignatureIdentity(app)
		var t AppTrust
		if k, ok := known[app]; ok && k.Identity == id && id != "" && !k.At.After(ctx.Now) && ctx.Now.Sub(k.At) < 7*24*time.Hour {
			t = k.Trust
			kept[app] = k
		} else {
			t = r.Trust(app)
			if id != "" {
				kept[app] = keptTrust{Identity: id, Trust: t, At: ctx.Now}
			}
		}
		name := NameWithoutExtension(app)
		ev := map[string]string{"added": ISODay(came)}
		if agent, ok := r.DownloadedBy(app); ok {
			if agent == "" {
				agent = "下载的（不知道用什么下的）"
			}
			ev["downloaded_by"] = agent
		} else {
			ev["quarantine"] = "没有下载标记：自己编译、从 App Store 或安装包装的，也可能下载后被人去掉了"
		}
		switch t.Kind {
		case TrustInvalid:
			ev["how"] = "别打开它；从开发者的官网重新下载"
			out = append(out, Finding{Rule: "apps.bad-signature", Category: CatMalware, Severity: High, Verdict: Confirm, Path: app,
				Title: "最近装的 " + name + " 签名和程序对不上（签名以后被改过）", Evidence: ev})
		case TrustUnsigned, TrustAdhoc:
			if t.Kind == TrustAdhoc && isWebApp(app, ctx.Home, ctx.AppDirs) {
				continue
			}
			ev["why"] = "只有临时签名"
			if t.Kind == TrustUnsigned {
				ev["why"] = "没有签名"
			}
			// No plan carries it (only what a virus database or YARA rule recognised): the user moves it.
			ev["how"] = "确认是你自己要装、来源可信的；不认识就在访达里把它移到废纸篓"
			out = append(out, Finding{Rule: "apps.unsigned", Category: CatMalware, Severity: Medium, Verdict: Confirm, Path: app,
				Title: "最近装的 " + name + " " + ev["why"] + "：谁做的、改没改过，没人担保", Evidence: ev})
		case TrustDeveloper:
			ev["team"] = t.Team
			ev["how"] = "多半是还没公证的老版本；从开发者官网换成新版本，或确认来源可信"
			ev["note"] = "只看本机已有的公证记录（没联网问苹果）：公证过、但没把记录附在应用里、又还没打开过的，也会出现在这里"
			out = append(out, Finding{Rule: "apps.not-notarized", Category: CatMalware, Severity: Low, Verdict: Info, Path: app,
				Title: "最近装的 " + name + " 有开发者签名（" + t.Team + "），本机没找到苹果的公证记录", Evidence: ev})
		}
	}
	return out, nil
}
