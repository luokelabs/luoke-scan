# Luoke Scan

*It sets a ward upon thy Mac, brushing away but what thou wilt not miss — and nothing past recall.*

[简体中文](README.md) | English

Checks your Mac while you are away: what is eating disk space and what can safely go; whether anything suspicious is there — programs that start by themselves, privacy grants, browser extensions, malware. Every finding says what it rests on, nothing is deleted until you click, and what is cleaned can be put back. Deterministic rules decide what is junk and how risky something is; a local model only puts it into words. Nothing leaves your Mac.

Luoke Scan (螺壳扫描, `luoke-scan`) is part of [Luoke](https://github.com/luokelabs/luoke) by Luoke Labs. **The app's interface is in Chinese for now.** Interface labels below are given in Chinese with a translation.

## What it is and where it sits in Luoke

Luoke is a family of local AI tools made by Luoke Labs (螺壳实验室); Luoke Scan is the app that looks after the Mac itself. It only checks, and cleans what you clicked: Luoke ([luoke-core](https://github.com/luokelabs/luoke-core)) schedules its rounds for when you are not using the computer and provides the local model it uses for explanations; what needs your decision is handed to Luoke, which picks the moment to tell you on a card; what happened (a clean-up, say) goes into Luoke Memory ([luoke-mem](https://github.com/luokelabs/luoke-mem)), shared by all Luoke apps. For how the pieces fit together see the top-level repository [luokelabs/luoke](https://github.com/luokelabs/luoke) and the [system docs](https://luokelabs.github.io/luoke-atlas/).

## Status

- **In closed beta**, first shipped with beta 2 (the version is in [`packaging/luoke-accessory.json`](packaging/luoke-accessory.json); the rule pack's, in `luoke-scan version`).
- **System**: Apple silicon (M1 or later), macOS 26.2 or later, 16 GB of memory or more, 32 GB or more recommended. These are Luoke's requirements; Luoke Scan itself also needs macOS 26.2 and is built for Apple silicon only.
- **How it runs**: at most one round a day, only on power and while you are not using the computer; when you come back it stops after the step in hand and the next round carries on. From the second round on it looks again only at what changed (from macOS's record of file changes). Later it will also glance at new downloads between rounds every few minutes, virus scan only, and not on battery, in Low Power Mode or under memory pressure (once Luoke has a way to start it; there is none yet).
- **Local model**: three things — explaining, naming folders, reading AI skills — use the model Luoke provides; when Luoke's model is off, the scan still runs and reports, only without those notes.
- **Interface**: Chinese.

## Getting it

Download Luoke from [luoke.ai](https://luoke.ai) and turn on Luoke Scan under 「应用」 (Apps) in Luoke. The virus scanners (ClamAV, YARA) come with the app and when there is no virus database yet, the first round downloads it before it checks; there is nothing to install yourself.

After that you can leave it alone: it checks once a day, and when something needs your decision Luoke tells you on a card. A clean-up plan lists what goes, how big it is and why, and happens only when you click. All findings and the clean-up log can be seen in Luoke too (「概览」 Overview, 「清理记录」 Clean-up log). To let it check everything, turn on 「螺壳」 (Luoke) under System Settings → Privacy & Security → Full Disk Access (optional; see "Data and privacy" below).

## What it checks

**Space**

- **Where the space goes and what grows**: the home folder, a few data folders in `~/Library` and the temp folder are measured once a day; anything growing by 1 GB a day or more is pointed out. Low free space is reported too (with the size of the swap files).
- **Caches that rebuild themselves**: the caches of pip, SwiftPM, Go, Cargo, Bun, uv, npm, Homebrew, Yarn, CocoaPods, Gradle, Poetry, node-gyp and Composer, Xcode's DerivedData and documentation cache, the simulators' cache. Delete them and the tool downloads or builds them again when needed; nothing of yours is lost.
- **Temp folders piling up**: many temp folders with the same prefix left behind (typically a test run that leaves a copy every time), with count, size and growth per day, so the source can be fixed.
- **Leftovers**: data of apps you removed, in `~/Library` and in the system's `/Library`; installers in Downloads for apps installed long ago, unfinished downloads; old files moved aside by macOS upgrades; an unused old Intel Homebrew on an Apple silicon Mac. Anything named like a wallet, password vault, key or VPN configuration is only mentioned, never suggested for deletion.
- **Untouched for a long time**: projects nobody touched for six months (git is checked first: unpushed commits, uncommitted changes, stashes, no remote — any of these and it is only mentioned, with what would be lost), dependencies and build output in old projects that can be made again, large files not opened for a year (as Spotlight knows it).
- **Duplicates**: large files with identical contents in Downloads, Desktop, Documents, Movies, Music and Pictures; APFS clones and hard links do not count (they take no extra space). A copy can go to the Trash, or be replaced by a clone: every copy stays and the extra space comes back.
- **System level**: Time Machine local snapshots kept for more than 2 days, the disks of container and VM tools (Docker, OrbStack, colima, Podman, lume), models downloaded by AI tools (Hugging Face's shared store counted by what its files really take), the restore images (`.ipsw`) left after installing a system, Xcode's old device support files, archives and simulators.

**Security**

- **Programs that start by themselves**: LaunchAgents and LaunchDaemons, background items and login items apps registered, crontab, folders that shell configuration adds to PATH; ones pointing at programs that no longer exist, with a broken signature, or system-wide jobs whose program you yourself can replace. **New since the last round and vouched for by nobody** (unsigned, ad hoc signed, a script, in a place you can write) is reported as urgent.
- **Other ways to start code**: environment variables that inject a library into other programs, authorization plugins, login hooks, a command Terminal runs for every new window, iTerm2 scripts that start with it, periodic scripts.
- **Recently installed apps**: apps put into Applications in the last 30 days whose signature is broken, missing or not notarized, with the program that downloaded them.
- **Processes**: still running though their program was deleted, piling up by the same program under one parent, or running for a long time after their parent went away.
- **Keyboard watchers**: which programs listen to every key pressed; one nobody vouches for is reported on its own.
- **Exposure**: ports listening beyond this Mac, passwords and tokens on the command lines of running programs, `~/.ssh` permissions, private keys without a passphrase or with a weak algorithm.
- **Plain-text credentials and stray keys**: tokens and passwords tools keep in plain text (`.git-credentials`, `.netrc`, `.npmrc` …), private keys, certificate bundles and cloud keys lying in Downloads, Desktop or Documents. Only where and what kind is recorded, never the value.
- **Browser extensions**: extensions that can read and change every site, ones forced by policy, ones not from a store, and the programs on this Mac an extension can start (Chromium-based browsers and Firefox; Safari is not looked at).
- **AI tools**: which servers the MCP configurations start and whether those files hold keys in plain text; risky patterns in the AI skills installed on this Mac (folders with a `SKILL.md`): reading keys and sending them out, running code fresh from the network, making themselves start at login, changing the AI's settings or memory, hidden text … (see [docs/skills.md](docs/skills.md), in Chinese).
- **Dependencies' install scripts**: the `preinstall`, `install` and `postinstall` of npm packages in your projects and installed globally, and the files they run, plus the `setup.py` of Python packages installed from source into a project's virtual environment: reading keys and sending them out, running code fresh from the network, decoding hidden code to run it, running secret scanners, pushing workflows into repositories, publishing packages with your token, making something start at login. Reported by rule as to confirm, not as urgent; the usual legitimate work (building native modules, downloading the package's own prebuilt binary) is not reported (see [docs/install-scripts.md](docs/install-scripts.md), in Chinese).
- **Privacy grants**: apps already removed that still hold Full Disk Access, Accessibility, Screen Recording and the like.
- **Package managers' install scripts**: whether the npm, pnpm, Yarn, pip and uv you use let the packages they install run their own scripts (`postinstall` and the like; a Python source package's `setup.py`). Only versions found on disk count (npm 12, pnpm 10 and Yarn 4.14 already block them by default; with several installed, the newest counts), and only your own config is read (`~/.npmrc`, `~/.yarnrc.yml`, `pip.conf`, `~/.config/uv/uv.toml`, pnpm's global config), never a project's. One finding per tool, to confirm, listing which installed dependencies really run scripts and how to let one through, and suggesting that new versions wait a day before installing (advice only; nothing is changed for you).
- **Basic settings**: FileVault, firewall, SIP, Gatekeeper, screen lock, automatic updates, remote login and sharing, AirDrop for everyone, automatic login, root certificates someone added, XProtect not updated for a long time. Only bad states are reported.
- **Known malicious packages in dependencies**: projects' lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`) and globally installed packages (npm's global folders: the `package.json` of each package and of every package in its own `node_modules`, name and version only; pipx, uv tool, cargo install; the global lockfiles of bun, pnpm and yarn) are compared by name and version with a local list of known malicious packages (OSV's `MAL-` entries, from OpenSSF's malicious-packages); an entry for every version counts too. Packages installed from git, a local file or some other URL do not count (the same name is not the same package), and lockfiles in test-data and example folders are not looked at; a package of the same name from a company's own registry is still reported, saying where it came from. Only package names and versions are read, never the packages' code; the comparison happens on this Mac, so which packages you use never leaves it. A package on the list is reported as urgent, with what to do (remove `node_modules` or the virtual environment, move to a version not on the list, and if it was installed, change your tokens and keys); nothing in the project is deleted for you. For now the list is imported by hand (`luoke-scan malicious-import <OSV JSON, folder or .zip>`, no network; each import adds to the list, so ecosystems can be imported one at a time); a package used in many places is reported once, listing where; until a list has been imported, this check does not run and says nothing.
- **Malware**: ClamAV and YARA (plus the YARA rules of macOS's own XProtect) scan files downloaded in the last 30 days, the programs background jobs run, the programs running now (and the scripts interpreters such as node or python run, those in node_modules included; not macOS's own), and the files in AI skills; only what is new or changed. A virus database more than 14 days old is reported, and the scan goes on with it.

Each finding has a verdict — **放心删** (safe to delete: only rebuildable caches), **要确认** (confirm first) or **仅供参考** (for reference) — and its evidence: size and growth, times, signatures, git state, the rule's name and version, the virus database's version and date. A check that could not run (scanner missing, timed out, no permission) is shown as 「没扫描」 (not scanned) with the reason, never as "nothing found".

**What the local model does**: explains the findings a card asks you to look at in plain words; names folders that keep growing and data left by removed apps (from names, sizes and file counts only, without opening any file); for AI skills the rules reported, says whether what a skill does matches what it claims. All of it is only a note under the finding and changes no verdict or severity; it is checked again before it is shown, and anything with a URL, a command, a number it made up, or vouching for something is not shown.

## Promises

- **Rules decide, the model only explains**: whether something is junk, whether it can go and how risky it is are decided by deterministic rules; the same situation gets the same verdict every time.
- **Checking is read-only**: a round changes nothing.
- **Nothing is cleaned until you click**: a clean-up carries out only a plan Luoke Scan itself made and you clicked on a card; every item is checked again first (the same file, not a link, unchanged). A request that would change anything is refused without your click.
- **Once you turn it on, four kinds are cleaned without a click, and can be put back and turned off** (off until you click "clean automatically from now on"): caches that rebuild themselves (deleted); installers in Downloads, at least 14 days old, of apps already installed; duplicates in Downloads with another copy elsewhere; temp folders left by test tools (Puppeteer, Playwright, Lighthouse) — these three go to the Trash. Only the scheduled daily round does it, and it tells you every time; a kind you put something back from is not cleaned automatically again, and the whole thing can be turned off. Caches are deleted by Luoke Scan itself, never with a tool's own clean command. How these four are picked has its own evaluation, which must pick nothing wrong.
- **Deleting means moving to the Trash, and it can be put back**: whatever is cleaned goes to the Trash and into 「清理记录」 (the clean-up log), and until the Trash is emptied one click puts it back where it was (next to it, if something of the same name is there now). The only exceptions are two kinds whose deletion loses nothing: caches that rebuild themselves (whether you clicked or they were cleaned automatically: the space is free at once), and the dead links an old Intel Homebrew leaves behind; these are deleted outright and cannot be put back. What was moved out of system folders with your password is in the Trash too, but belongs to the system: drag it back in Finder (it asks for the password).
- **A setting is changed by one added line, and can be put back**: a package manager's 「改成不跑」 (don't run them) only appends one line to your own user config (a new `pip.conf` also gets a `[global]` line; a project's config is never touched), after checking it is still the file that was checked and no link is on the way (a config that is a symbolic or hard link, or whose folder on the way is a link, is not changed; you are told the line to add). The new file is written beside the old one and the two are swapped, so a whole config is always in place; if a program writes to it during the swap, it is swapped back and left alone. The previous file goes to the Trash and into the clean-up log, and putting back swaps it in again; if you changed the file since, yours stays and the previous one goes next to it; if the previous one is no longer in the Trash, the changed one is left as it is.
- **The password step does only the items you confirmed**: leftovers in the system's `/Library` and an old Intel Homebrew need administrator rights. After your click macOS's own password dialog appears, one authorisation each time, with no resident administrator helper installed; what runs as administrator is the separately signed `luoke-scan-admin`, whose signature is checked before it runs, which judges every item again and also moves it to the Trash.
- **Other accounts' files are never touched.**
- **No interruptions**: no notifications, no menu bar icon; what there is to say is handed to Luoke, which picks the moment.
- **Nothing leaves your Mac**: see the next section.

## Data and privacy

**On the device only**: scanning, judging and explaining all happen on your Mac; findings and file contents are never uploaded, and Luoke has no server.

**What it reads**: most checks look only at metadata (name, size, times, owner, signature, link count) and open no file. Contents are read only for: duplicates (SHA-256, remembered so an unchanged file is not read again), the lockfiles of projects and global installs and the `package.json` of globally installed npm packages (package names and versions only), plain-text credentials and stray keys (only the first bytes of small files), AI skills (read into memory and let go after the check), dependencies' install scripts (only each package's `package.json` and the files its install hooks run, never the whole of `node_modules`; what was read is remembered and not read again while unchanged, without its contents), the configuration files being checked (background jobs, browser extensions, MCP, shell configuration), and the virus scan (ClamAV and YARA read the files they scan). Contents never go into logs, memory or cards; passwords, keys and tokens found are recorded only by where and what kind, never the value. What goes to the local model: for explanations, a finding's verdict, title, location, size and evidence; for naming folders, metadata only; for skills, the skill's name, description and trimmed contents (6,000 characters at most in all). The model runs inside Luoke.

**When it goes online** (checked against the code; the Luoke Scan section of Luoke's network inventory):

- **Virus database**: at most once a day, freshclam downloads ClamAV's virus database from `database.clamav.net` (by default freshclam also looks up a DNS record at `current.cvd.clamav.net` first, to see whether there is a new one). Download only, nothing is uploaded; every new database file is verified against ClamAV's root certificate (which comes with the app) before it replaces the old, and on failure the old one stays.
- **The malicious-package list is not downloaded**: it is imported only from local files you give it (`luoke-scan malicious-import`), and compared only on this Mac.
- **Nothing else goes online**: git only reads locally (no fetch); the model and the memory are reached through Luoke on the same Mac; the interface for Luoke's agent opens no socket and no network port: Luoke starts the scanner once per request and talks to it over its standard input and output.
- When you click 「在访达里显示」 (Show in Finder) or 「打开设置」 (Open Settings) on a card, macOS opens Finder or System Settings.

Model output never makes the program connect anywhere, nor delete anything.

**Where data lives**: `~/.luoke-scan/`, readable only by your account (700), excluded from Time Machine.

- No database: each kind of record is a snapshot (`<name>.json`) plus a log of the changes after it (`<name>.log`, one line per batch, with a checksum), and `<name>.lock` is its lock. They hold the history of folder sizes (`sizes`), what was measured and checked (`measured`, `project_state`, `leftover_state`, `temp_entries`; the next round looks again only at what changed), hashes of duplicates (`file_hashes`), files scanned for malware (`malware_scanned`), the self-starting programs seen so far (`seen-persistence`), the model's answers (`model_answers`), and small facts such as the virus database's state (`meta`). All of it is a cache: one that cannot be read is dropped and the next round rebuilds it
- `last-report.json`: the last round's findings
- `progress.json`: how far the round running now has got (removed when it ends)
- `agent-state.json`: what you were told, what you said not to mention, the switch for cleaning without a click
- `cleaned.jsonl`: the clean-up log (what went to the Trash and where it was), which putting back relies on
- `plans/`: the clean-up plans shown on cards
- `vitals.json`, `vitals.log`: how much processor time each program had used at the last round (process ids, start times and seconds only), so that the next round can tell which one keeps a core busy
- `clamav/`, `clamav-quick/`: the virus database
- `malicious-packages.txt`: the imported list of malicious packages (ecosystem, name, MAL id, affected versions; its date at the top)

What goes into Luoke Memory is only what happened: which kind you cleaned, which kind you said not to mention, what was cleaned automatically, what became of a malware alert, whether cleaning without a click is on; never a path, a folder's contents or a hash (a malware alert carries only the file name).

**Full Disk Access is optional**: it is granted to Luoke itself (top-level [ADR 0021](https://github.com/luokelabs/luoke/blob/main/docs/adr/0021-full-disk-access-belongs-to-luoke.md)), and the scanner programs Luoke starts use that grant; you do not give it to Luoke Scan separately. Without it the scan stays out of every place macOS would ask you about (Desktop, Documents, Downloads, iCloud Drive, other apps' data); those parts are shown as not checked, with the reason, never as fine; everything else is checked as usual. With it, malware in Downloads, duplicates, stray keys, other apps' leftovers and stale privacy grants are checked in full. Luoke tells you when something could not be checked for lack of it; the place to turn it on is 「螺壳」 (Luoke) under System Settings → Privacy & Security → Full Disk Access.

## Security design

- **Two programs**: `luoke-scan` scans and cleans; it never opens a socket or listens on the network: the tools for Luoke's agent (MCP) go over the standard input and output of `luoke-scan mcp`, which Luoke's main app starts. `luoke-scan-admin` runs only after you entered your password in Luoke's dialog, as administrator, for that one deletion.
- Only Luoke's main app shows the password dialog: the scan hands it only which items of which plan, and the main app builds the command root runs — it copies the `luoke-scan-admin` in its own bundle into a folder only root can write, checks its signature there (Luoke's developer signature), then runs it with an empty environment; nothing the scan says becomes part of that command. You can also do it yourself in a terminal (`luoke-scan system`, through sudo, with the same signature check).
- External commands (git, clamscan, yara …) all run with time limits. Scans (the scheduled ones and the round the agent asks for) and the virus-database update lower their own priority as they start (CPU and disk both give way to the apps you are using), and the commands they start inherit it; `luoke-scan mcp`, which answers the agent (and carries out a plan you clicked), is not lowered. git runs with the repository settings that would start programs turned off (fsmonitor, hooks and the like), so a scanned repository cannot make git run a program of its own.
- The installed .app accepts only `--this-mac`, none of the development options, and uses only the scanners that came with it.
- The bundled third-party programs and libraries are separate processes; Luoke Scan does not link them, see [NOTICE](NOTICE).

## Building from source and development

For developers; everyone else, please use Luoke above.

You need an Apple silicon Mac, macOS 26.2 or later, Go 1.25 or later (`go.mod` pins the toolchain; an older `go` switches to that version by itself) and Xcode's command line tools (cgo needs a C compiler: the FSEvents journal, the keyboard taps and the volume's capacity use macOS frameworks). The only third-party package is the Go team's `golang.org/x/sys`. Packaging an .app also needs Homebrew's `clamav` and `yara` ([`scripts/package_app.py`](scripts/package_app.py)); development and tests do not.

```bash
git clone https://github.com/luokelabs/luoke-scan.git
cd luoke-scan
go build -o .build/go/luoke-scan ./cmd/luoke-scan
go test ./...
python3 -I blackbox/run.py      # black-box tests: a few hundred scenarios, a few minutes
```

If the `clang` on your PATH does not work (another toolchain's shim, say), put `CC=/usr/bin/clang` before the commands.

Tests use only generated fake homes and fake scanners (the fake clamscan, freshclam, sigtool and yara are shell scripts), read and write only in temporary folders, and never touch your home folder, go online or show a dialog. The black-box tests ([`blackbox/`](blackbox/README.md)) run `luoke-scan` only through its command line and compare with recorded answers, character for character.

To try the command line on a fake home with known answers, let the black-box tests keep the fake home they make, then run against it:

```bash
python3 -I blackbox/run.py --only base/two-rounds --keep             # prints where the fake home is
.build/go/luoke-scan scan --fixture <fake home> --clock 2026-10-20T12:00:00Z   # processes and system settings are fake too
.build/go/luoke-scan report --data <fake home>/data                     # listed by safe to delete, confirm first, for reference
```

During development always use a fake home and a data folder of your own: `--home <fake home> --data .dev/<name>` (`.dev/` is not in git), never the real home folder or `~/.luoke-scan`. `--home` replaces only the home folder — processes, system settings and so on are still read from this Mac (read-only); `--fixture` replaces those as well. `luoke-scan` without arguments lists every command.

### Evaluation

```bash
.build/go/luoke-scan eval-cleanup       # the four kinds cleaned without a click: 72 cases, must pick nothing wrong
.build/go/luoke-scan eval-skills        # the AI skill checks: 33 malicious and 33 benign synthetic skills
.build/go/luoke-scan eval-agentfiles    # the checks on files AI tools read (AGENTS.md, CLAUDE.md…): 13 malicious, 13 benign
python3 bench/test_checks.py               # whether the evaluation's own checks are right; no model needed
```

The evaluation sets of the three generation tasks (explain, identify — naming folders, skills) are in `bench/evalsets/`, all synthetic; the prompts are in `prompts/`, and what the scan sends to the model is byte for byte what the evaluation sends. Any OpenAI-compatible local model service on 127.0.0.1 can be tested:

```bash
python3 bench/run_eval.py --endpoint http://127.0.0.1:<port> --model <model> --label <label> --out .dev/evals                # explain, identify
python3 bench/run_eval.py --endpoint http://127.0.0.1:<port> --model <model> --task skills --label <label> --out .dev/evals   # skills
```

Every item has deterministic checks and passes only if all of them pass; the exit code is 1 when a hard item fails. Earlier results (`bench/results/`, 2026-10-23, an M3 Ultra through a local endpoint, temperature 0, an item passes only if all 3 runs pass):

| Model | explain | identify |
|---|---|---|
| Qwen3.5-9B 4-bit | 31/32, hard 13/13 | 29/30, hard 8/8 |
| gemma-4-26B 8-bit | 29/32, hard 13/13 | 29/30, hard 8/8 |

For the skills results and how its prompt went through several versions, see [docs/skills.md](docs/skills.md) (in Chinese).

## Documentation

- [docs/skills.md](docs/skills.md): checking the AI skills on this Mac (where it looks, the ten kinds of checks, privacy, the semantic check and its evaluation), in Chinese
- [docs/install-scripts.md](docs/install-scripts.md): checking dependencies' install scripts (where it looks, which files it follows, what is and is not reported, limits, false-positive measurement), in Chinese
- [evals/cleanup/README.md](evals/cleanup/README.md): the evaluation of the four kinds cleaned without a click, with the look-alike cases for each kind that must not be cleaned, in Chinese
- [fixtures/agent/README.md](fixtures/agent/README.md): scenario fixtures for the agent: what the scanner really answers in a few situations (outbox, cards, base pages, permissions), recorded by `scripts/record_agent_fixtures.py`, in Chinese
- [evals/skills/README.md](evals/skills/README.md): the synthetic evaluation set for the skill checks, in Chinese
- [bench/](bench/): evaluation of the generation tasks (`run_eval.py`, `evalsets/`, `results/`) and the performance benchmark (`perf.py`, usage at the top of the file)
- [prompts/](prompts/): the prompts of the three generation tasks (one set of files per task)
- [CONTEXT.md](CONTEXT.md): glossary, in Chinese
- [scripts/package_app.py](scripts/package_app.py): packaging, signing and checking; what is in the app is described at the top
- How Luoke is divided and decisions across components: `ARCHITECTURE.md` and `docs/adr/` in the top-level repository [luokelabs/luoke](https://github.com/luokelabs/luoke) (0013 the machine is the boundary, 0016 acting for the user, 0018 models belong to Luoke, 0021 Full Disk Access belongs to Luoke)

## License, security, contributing

- License: Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright © Luoke Labs (螺壳实验室). ClamAV and the other bundled third-party components are under their own licenses, see NOTICE.
- Please report security issues privately, see [SECURITY.md](SECURITY.md).
- Issues are welcome; please open one to discuss a change first, see [CONTRIBUTING.md](CONTRIBUTING.md).
