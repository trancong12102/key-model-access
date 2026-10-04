package main

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestSettingsPageAppliesThemeBeforeFirstPaint(t *testing.T) {
	raw, err := settingsPage()
	if err != nil {
		t.Fatalf("settingsPage() error = %v", err)
	}
	var response managementResponse
	unwrapEnvelope(t, raw, &response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	body := string(response.Body)
	nonce := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(response.Headers.Get("Content-Security-Policy"))
	if len(nonce) != 2 {
		t.Fatal("CSP nonce missing")
	}
	themeJS, err := webAssets.ReadFile("web/theme.js")
	if err != nil {
		t.Fatal(err)
	}

	head := body[:strings.Index(body, "<body>")]
	themeTag := strings.Index(head, `<script nonce="`+nonce[1]+`">`+string(themeJS)+`</script>`)
	if themeTag == -1 {
		t.Fatal("the nonce'd theme script must be inside <head>")
	}
	if style := strings.Index(head, "<style"); style == -1 || themeTag > style {
		t.Fatal("the theme script must run before the stylesheet is applied")
	}
	if strings.Count(body, "<script") != strings.Count(body, `<script nonce="`+nonce[1]+`">`) {
		t.Fatal("every inline script must carry the per-response CSP nonce")
	}
	if strings.Contains(body, "{{THEME_JS}}") {
		t.Fatal("theme script placeholder was not replaced")
	}
}

func TestThemeScriptAppliesCPAMCThemeSynchronously(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	themeJS, err := webAssets.ReadFile("web/theme.js")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, setup, want string
	}{
		{"stored dark theme", `store["cli-proxy-theme"] = JSON.stringify({state:{theme:"dark"}});`, "dark"},
		{"stored white theme", `store["cli-proxy-theme"] = JSON.stringify({state:{theme:"white"}});`, "white"},
		{"stored auto follows dark system", `store["cli-proxy-theme"] = JSON.stringify({state:{theme:"auto"}}); systemDark = true;`, "dark"},
		{"no stored theme follows dark system", `systemDark = true;`, "dark"},
		{"stored light theme", `store["cli-proxy-theme"] = JSON.stringify({state:{theme:"light"}});`, "null"},
		{"dark CPAMC parent wins over storage", `store["cli-proxy-theme"] = JSON.stringify({state:{theme:"light"}}); parentTheme = "dark";`, "dark"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			harness := `
const store = {};
let systemDark = false;
let parentTheme = undefined;
const dataset = {};
const classes = {};
const documentElement = {
    dataset: dataset,
    getAttribute: function(name) { return name === "data-theme" && "theme" in dataset ? dataset.theme : null; },
    removeAttribute: function(name) { if (name === "data-theme") delete dataset.theme; },
    classList: { toggle: function(name, on) { classes[name] = Boolean(on); } }
};
globalThis.document = { documentElement: documentElement };
globalThis.localStorage = { getItem: function(name) { return name in store ? store[name] : null; } };
const storageListeners = [];
globalThis.MutationObserver = function() { this.observe = function() {}; };
const win = { matchMedia: function() { return { matches: systemDark }; }, addEventListener: function(type, fn) { if (type === "storage") storageListeners.push(fn); } };
globalThis.window = win;
` + tc.setup + `
win.self = win;
if (parentTheme !== undefined) {
    win.top = {};
    win.parent = { document: { documentElement: { getAttribute: function() { return parentTheme; } } } };
} else {
    win.top = win;
}
` + string(themeJS) + `
const got = documentElement.getAttribute("data-theme");
if (String(got) !== ` + strconv.Quote(tc.want) + `) {
    console.error("data-theme = " + got + ", want ` + tc.want + `");
    process.exit(1);
}
if (classes["is-embedded"] !== (parentTheme !== undefined)) {
    console.error("is-embedded class not set before first paint");
    process.exit(1);
}
if (parentTheme === undefined) {
    store["cli-proxy-theme"] = JSON.stringify({state:{theme:"dark"}});
    storageListeners.forEach(function(fn) { fn({ key: "cli-proxy-theme" }); });
    if (documentElement.getAttribute("data-theme") !== "dark") {
        console.error("a CPAMC theme change in another document must re-sync the page");
        process.exit(1);
    }
}
`
			path := filepath.Join(t.TempDir(), "theme.js")
			if err := os.WriteFile(path, []byte(harness), 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command(node, path).CombinedOutput(); err != nil {
				t.Fatalf("theme script fixture failed: %v\n%s", err, output)
			}
		})
	}
}
