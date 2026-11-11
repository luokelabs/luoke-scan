package core

// The curated lists as they were written in Go before they moved into rules/ (2026-11-09), copied from that code. Only
// the type names changed; vmTools' explain is what Run said of each (one text for lume, one for the others), aiTools'
// models what modelFolders did (Hugging Face's layout for Hugging Face, publisher/model for the other model folders).
// TestRulesDataAsBeforeTheMove holds the files to them.

var preMoveCaches = []RebuildableCache{
	// Not `pip cache purge`: an older pip (e.g. the system one) leaves a newer pip's http-v2 cache behind.
	{ID: "pip", Path: "Library/Caches/pip", Tool: "pip", Clean: "删除这个文件夹"},
	{ID: "swiftpm", Path: "Library/Caches/org.swift.swiftpm", Tool: "SwiftPM", Clean: "删除这个文件夹"},
	{ID: "go-build", Path: "Library/Caches/go-build", Tool: "Go", Clean: "go clean -cache", Command: "go",
		Env: map[string]string{"GOCACHE": "Library/Caches/go-build"}},
	{ID: "xcode-deriveddata", Path: "Library/Developer/Xcode/DerivedData", Tool: "Xcode", Clean: "删除这个文件夹（Xcode 没开着时）"},
	{ID: "cargo-registry-cache", Path: ".cargo/registry/cache", Tool: "Cargo", Clean: "删除这个文件夹"},
	{ID: "cargo-registry-src", Path: ".cargo/registry/src", Tool: "Cargo", Clean: "删除这个文件夹"},
	{ID: "bun", Path: ".bun/install/cache", Tool: "Bun", Clean: "删除这个文件夹"},
	{ID: "uv", Path: ".cache/uv", Tool: "uv", Clean: "uv cache clean", Command: "uv", Env: map[string]string{"UV_CACHE_DIR": ".cache/uv"}},
	// npm's own cache only; ~/.npm/_npx holds packages that running tools (e.g. MCP servers) use.
	{ID: "npm", Path: ".npm/_cacache", Tool: "npm", Clean: "npm cache clean --force", Command: "npm",
		Env: map[string]string{"npm_config_cache": ".npm"}},
	// Downloaded bottles, sources and the formula list; not `brew cleanup`, which also removes old installed versions.
	{ID: "homebrew", Path: "Library/Caches/Homebrew", Tool: "Homebrew", Clean: "删除这个文件夹"},
	// Yarn 1's download cache. Not Yarn 2+'s global cache (~/.yarn/berry/cache): Plug'n'Play projects load their
	// packages straight from it, and nothing fetches them again until an install.
	{ID: "yarn", Path: "Library/Caches/Yarn", Tool: "Yarn", Clean: "删除这个文件夹"},
	{ID: "cocoapods", Path: "Library/Caches/CocoaPods", Tool: "CocoaPods", Clean: "删除这个文件夹"},
	{ID: "gradle-caches", Path: ".gradle/caches", Tool: "Gradle", Clean: "删除这个文件夹（Gradle 没在跑时）"},
	{ID: "gradle-wrapper", Path: ".gradle/wrapper/dists", Tool: "Gradle", Clean: "删除这个文件夹（各项目的 gradlew 用到时会重新下载）"},
	// Not all of pypoetry: its virtualenvs (the projects' environments) live there too.
	{ID: "poetry-cache", Path: "Library/Caches/pypoetry/cache", Tool: "Poetry", Clean: "删除这个文件夹"},
	{ID: "poetry-artifacts", Path: "Library/Caches/pypoetry/artifacts", Tool: "Poetry", Clean: "删除这个文件夹"},
	// Not Deno's folder (its location_data holds apps' local databases), not pre-commit's (it keeps the unstaged
	// changes it set aside while hooks run there, as patches).
	{ID: "node-gyp", Path: "Library/Caches/node-gyp", Tool: "node-gyp", Clean: "删除这个文件夹"},
	{ID: "composer", Path: "Library/Caches/composer", Tool: "Composer", Clean: "删除这个文件夹"},
	{ID: "xcode-documentation", Path: "Library/Developer/Xcode/DocumentationCache", Tool: "Xcode", Clean: "删除这个文件夹（Xcode 没开着时）"},
	// Shared caches the simulators build on first boot; not Devices (the simulators and the apps' data in them).
	{ID: "coresimulator-caches", Path: "Library/Developer/CoreSimulator/Caches", Tool: "模拟器", Clean: "删除这个文件夹（模拟器没开着时）"},
	// The simulators Xcode clones to run tests in parallel; it clones them again for the next run.
	{ID: "xctest-devices", Path: "Library/Developer/XCTestDevices", Tool: "Xcode 测试用的模拟器", Clean: "删除这个文件夹（Xcode 没在跑测试时）"},
	{ID: "xcode-cache", Path: "Library/Caches/com.apple.dt.Xcode", Tool: "Xcode", Clean: "删除这个文件夹（Xcode 没开着时）"},
	// The package managers Corepack downloaded (pnpm, Yarn); it downloads the one a project asks for again.
	{ID: "corepack", Path: ".cache/node/corepack", Tool: "Corepack", Clean: "删除这个文件夹"},
}

var preMoveCacheUsers = map[string][]string{
	"pip": {"pip", "pip3"}, "swiftpm": {"swift-build", "swift-package", "swift-test", "swift-run", "xcodebuild", "Xcode"},
	"go-build": {"go", "gopls"}, "xcode-deriveddata": {"Xcode", "xcodebuild", "SourceKitService"},
	"cargo-registry-cache": {"cargo", "rustc"}, "cargo-registry-src": {"cargo", "rustc", "rust-analyzer"},
	"bun": {"bun"}, "uv": {"uv"}, "npm": {"npm", "npx"},
	// brew runs as bash, then Homebrew's own ruby. Homebrew's yarn runs as yarn.js.
	"homebrew": {"brew", "ruby"}, "yarn": {"yarn", "yarn.js"}, "cocoapods": {"pod"},
	"gradle-caches": {"gradle", "gradlew", "java"}, "gradle-wrapper": {"gradle", "gradlew", "java"},
	"poetry-cache": {"poetry"}, "poetry-artifacts": {"poetry"}, "node-gyp": {"node-gyp", "npm", "npx"},
	"composer": {"composer"}, "xcode-documentation": {"Xcode"},
	"coresimulator-caches": {"Simulator", "simctl", "com.apple.CoreSimulator.CoreSimulatorService", "launchd_sim", "Xcode", "xcodebuild"},
	"xctest-devices":       {"Simulator", "simctl", "com.apple.CoreSimulator.CoreSimulatorService", "launchd_sim", "Xcode", "xcodebuild"},
	"xcode-cache":          {"Xcode", "xcodebuild", "SourceKitService"},
	"corepack":             {"corepack", "node", "npm", "npx", "pnpm", "yarn"},
}

var preMoveTemp = map[string]string{
	"puppeteer_dev_chrome_profile": "Puppeteer", "puppeteer_dev_firefox_profile": "Puppeteer",
	"playwright_chromiumdev_profile": "Playwright", "playwright_firefoxdev_profile": "Playwright",
	"playwright-artifacts": "Playwright", "lighthouse": "Lighthouse",
}

var preMoveWaitForTool = map[string]bool{"playwright-artifacts": true}

var preMoveVMTools = []vmTool{
	{tool: "Docker Desktop", paths: []string{"Library/Containers/com.docker.docker/Data/vms"},
		explain: "镜像、容器、数据卷和构建缓存都在这块虚拟磁盘里，删了的东西不一定会把空间还回来",
		how:     "`docker system df` 看占在哪，`docker system prune` 清掉不用的镜像、容器和构建缓存；虚拟磁盘的上限在 Docker Desktop 的 设置 → Resources"},
	{tool: "OrbStack", paths: []string{".orbstack/data", "Library/Group Containers/HUAQ24HBR6.dev.orbstack/data"},
		explain: "镜像、容器、数据卷和构建缓存都在这块虚拟磁盘里，删了的东西不一定会把空间还回来",
		how:     "`docker system prune` 清掉不用的；OrbStack 会把空出来的空间还给系统"},
	{tool: "colima", paths: []string{".colima", ".lima"},
		explain: "镜像、容器、数据卷和构建缓存都在这块虚拟磁盘里，删了的东西不一定会把空间还回来",
		how:     "`docker system prune` 清掉不用的；整台虚拟机都不要了用 `colima delete`（里面的东西都会没）"},
	{tool: "Podman", paths: []string{".local/share/containers/podman/machine"},
		explain: "镜像、容器、数据卷和构建缓存都在这块虚拟磁盘里，删了的东西不一定会把空间还回来",
		how:     "`podman system prune` 清掉不用的；不要了用 `podman machine rm`"},
	{tool: "lume", paths: []string{".lume"},
		explain: "每台 macOS 虚拟机一个文件夹，里面是它的整块硬盘；虚拟机里删了东西，这里不一定变小",
		how:     "`lume ls` 看有哪些虚拟机，用不到的 `lume delete <名字>` 删掉（那台虚拟机里的东西都会没）"},
}

var preMoveVMMarkers = map[string]vmSign{"Docker Desktop": {".docker", "Docker.app"}, "OrbStack": {".orbstack", "OrbStack.app"}}

var preMoveAITools = []aiTool{
	{"Hugging Face", ".cache/huggingface/hub", modelsHuggingFace, "用不到了就删；再用时会重新下载"},
	{"LM Studio", ".lmstudio/models", modelsPublisher, "用不到了在 LM Studio 里删，或删这个文件夹；再用时会重新下载"},
	{"LM Studio", ".cache/lm-studio/models", modelsPublisher, "用不到了在 LM Studio 里删，或删这个文件夹；再用时会重新下载"},
	{"Ollama", ".ollama/models", "", "`ollama list` 看有哪些，`ollama rm <名字>` 删掉用不到的"},
	{"PyTorch", ".cache/torch", "", "里面是下载的模型权重，删了用到时会重新下载"},
	{"Whisper", ".cache/whisper", "", "里面是语音识别模型，删了用到时会重新下载"},
	{"GPT4All", "Library/Application Support/nomic.ai/GPT4All", "", "在 GPT4All 里删掉用不到的模型；再用时会重新下载"},
	{"Jan", "Library/Application Support/Jan/data/models", "", "在 Jan 里删掉用不到的模型；再用时会重新下载"},
	{"Jan", "jan/models", "", "在 Jan 里删掉用不到的模型；再用时会重新下载"},
	{"DiffusionBee", ".diffusionbee/downloads", "", "在 DiffusionBee 里删掉用不到的模型；再用时会重新下载"},
	{"Draw Things", "Library/Containers/com.liuliu.draw-things/Data/Documents/Models", "", "在 Draw Things 里删掉用不到的模型；再用时会重新下载"},
	{"应用自带的 Hugging Face", "Documents/huggingface/models", "", "下载它的应用用不到了就删；再用时会重新下载"},
}

var preMoveArtifactKinds = []staleArtifactKind{
	{"node_modules", []string{"package.json"}, "", "npm install（或 yarn、pnpm）"},
	{".next", []string{"package.json"}, "", "重新构建"},
	{".nuxt", []string{"package.json"}, "", "重新构建"},
	{".svelte-kit", []string{"package.json"}, "", "重新构建"},
	{".turbo", []string{"package.json"}, "", "重新构建"},
	{".parcel-cache", []string{"package.json"}, "", "重新构建"},
	{"target", []string{"Cargo.toml"}, "", "cargo build"},
	{"target", []string{"pom.xml"}, "", "mvn package"},
	{".build", []string{"Package.swift"}, "", "swift build"},
	{"build", []string{"build.gradle", "build.gradle.kts"}, "", "gradle build"},
	{".gradle", []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}, "", "gradle build"},
	{"build", []string{"CMakeLists.txt"}, "CMakeCache.txt", "cmake 再配置、构建一遍"},
	{"Pods", []string{"Podfile"}, "", "pod install"},
	{"DerivedData", []string{"*.xcodeproj", "*.xcworkspace"}, "", "在 Xcode 里构建"},
	{".venv", []string{"pyproject.toml", "requirements.txt", "setup.py", "Pipfile"}, "pyvenv.cfg", "重新建虚拟环境、装依赖"},
	{"venv", []string{"pyproject.toml", "requirements.txt", "setup.py", "Pipfile"}, "pyvenv.cfg", "重新建虚拟环境、装依赖"},
	{".tox", []string{"tox.ini"}, "", "tox"},
	{".dart_tool", []string{"pubspec.yaml"}, "", "dart pub get"},
	{".zig-cache", []string{"build.zig"}, "", "zig build"},
	{"zig-cache", []string{"build.zig"}, "", "zig build"},
	{".stack-work", []string{"stack.yaml"}, "", "stack build"},
	{"_build", []string{"mix.exs"}, "", "mix compile"},
	{"deps", []string{"mix.exs"}, "", "mix deps.get"},
	{"Library", []string{"ProjectSettings/ProjectVersion.txt"}, "", "用 Unity 打开项目，它会重新导入"},
	{"Temp", []string{"ProjectSettings/ProjectVersion.txt"}, "", "用 Unity 打开项目"},
}

var preMoveBrowsers = []chromiumBrowser{
	{"Chrome", "Library/Application Support/Google/Chrome", "com.google.Chrome"},
	{"Chrome Beta", "Library/Application Support/Google/Chrome Beta", "com.google.Chrome.beta"},
	{"Edge", "Library/Application Support/Microsoft Edge", "com.microsoft.Edge"},
	{"Brave", "Library/Application Support/BraveSoftware/Brave-Browser", "com.brave.Browser"},
	{"Arc", "Library/Application Support/Arc/User Data", "company.thebrowser.Browser"},
	{"Vivaldi", "Library/Application Support/Vivaldi", "com.vivaldi.Vivaldi"},
	{"Chromium", "Library/Application Support/Chromium", "org.chromium.Chromium"},
}

var preMoveMCPConfigs = []mcpConfig{
	{"Claude Code", ".claude.json", "mcpServers"},
	{"Claude 桌面版", "Library/Application Support/Claude/claude_desktop_config.json", "mcpServers"},
	{"Cursor", ".cursor/mcp.json", "mcpServers"},
	{"Windsurf", ".codeium/windsurf/mcp_config.json", "mcpServers"},
	{"VS Code", "Library/Application Support/Code/User/mcp.json", "servers"},
	{"Gemini CLI", ".gemini/settings.json", "mcpServers"},
	{"LM Studio", ".lmstudio/mcp.json", "mcpServers"},
}

// preMoveAutoCaches are the caches automatic cleaning took before the move: all of them.
var preMoveAutoCaches = []string{
	"pip", "swiftpm", "go-build", "xcode-deriveddata", "cargo-registry-cache", "cargo-registry-src", "bun", "uv", "npm",
	"homebrew", "yarn", "cocoapods", "gradle-caches", "gradle-wrapper", "poetry-cache", "poetry-artifacts", "node-gyp",
	"composer", "xcode-documentation", "coresimulator-caches", "xctest-devices", "xcode-cache", "corepack",
}

// preMoveAutoTemp are the temp folder prefixes automatic cleaning took before the move: all of them.
var preMoveAutoTemp = []string{"puppeteer_dev_chrome_profile", "puppeteer_dev_firefox_profile", "playwright_chromiumdev_profile",
	"playwright_firefoxdev_profile", "playwright-artifacts", "lighthouse"}
