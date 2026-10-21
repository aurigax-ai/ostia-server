package publish

import (
	"io/fs"
	"strings"
	"testing"

	shareshell "github.com/aurigax-ai/ostia-server/web/share-shell"
)

func TestDataResponsesAreSandboxed(t *testing.T) {
	if !strings.Contains(dataContentSecurityPolicy, "sandbox") {
		t.Fatalf("data responses must be sandboxed: %q", dataContentSecurityPolicy)
	}
}

func TestShellRendersTheArtifactInASandboxedFrameWithoutSameOrigin(t *testing.T) {
	shell, err := fs.ReadFile(shareshell.Files, "shell.js")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(shell), "iframe") != 1 || !strings.Contains(string(shell), "sandbox: 'allow-scripts'") {
		t.Fatal("the shell must create exactly one iframe, sandboxed with allow-scripts only")
	}
	err = fs.WalkDir(shareshell.Files, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := fs.ReadFile(shareshell.Files, path)
		if err != nil {
			return err
		}
		for _, banned := range []string{"allow-same-origin", "allow-top-navigation", "allow-popups", "allow-forms"} {
			if strings.Contains(string(content), banned) {
				t.Errorf("%s grants %s to the artifact", path, banned)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(shell), `"connect-src 'none'; form-action 'none'; base-uri 'none'"`) || !strings.Contains(string(shell), "doc.head.prepend(policy)") {
		t.Fatal("the artifact document must get its own policy that blocks connections to the share host")
	}
	if !strings.Contains(shellContentSecurityPolicy, "default-src 'none'") || !strings.Contains(shellContentSecurityPolicy, "frame-ancestors 'none'") {
		t.Fatalf("the shell's own policy: %q", shellContentSecurityPolicy)
	}
}

func TestNoticeBarIsOutsideTheFrameAndCannotBeSkipped(t *testing.T) {
	shell, err := fs.ReadFile(shareshell.Files, "shell.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(shell)
	for _, want := range []string{
		"Shared from Ostia · made by a user, not by Ostia ·",
		"This page was published by an Ostia user. Do not enter passwords or personal details.",
		"Show the page",
		"if (warning) document.body.prepend(renderBar())",
		"localStorage",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("shell.js lacks %q", want)
		}
	}
	if strings.Contains(js, "innerHTML") || strings.Contains(js, "document.cookie") {
		t.Error("the shell must not use innerHTML or cookies")
	}
	if strings.Contains(js, "root.replaceChildren(frame, ") || strings.Contains(js, "frame.append") {
		t.Error("the bar must not live inside the frame's container")
	}
	if strings.Count(js, "renderDocument(") != 3 || strings.Count(js, "renderWithNotice(") != 4 {
		t.Error("every artifact must pass through the interstitial")
	}
}

func TestOnlyTheOperatorControlsTheWarning(t *testing.T) {
	shell, err := fs.ReadFile(shareshell.Files, "shell.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(shell)
	for _, banned := range []string{"location.search", "URLSearchParams", "document.cookie", "location.hash.includes", "sessionStorage"} {
		if strings.Contains(js, banned) {
			t.Errorf("the shell reads %s, which a link could use to change the warning", banned)
		}
	}
	if strings.Count(js, "\n  warning = ") != 1 || !strings.Contains(js, "warning = meta.warning !== false") {
		t.Error("the warning must come from the server's meta only")
	}
	if !strings.Contains(js, "{ sandbox: 'allow-scripts', title: 'Shared artifact', class: 'artifact' }") {
		t.Error("the frame's attributes must be exactly sandbox=allow-scripts, a title and a class: no allow attribute")
	}
	if strings.Contains(js, "'allow'") || strings.Contains(js, "allowfullscreen") || strings.Contains(js, "setAttribute('allow") {
		t.Error("the frame must not carry an allow attribute")
	}
	accept := js[strings.Index(js, "show.addEventListener"):]
	accept = accept[:strings.Index(accept, "})")]
	if !strings.Contains(accept, "renderDocument(html)") || strings.Count(js, "renderDocument(html)") != 3 {
		t.Error("the frame may only be created after the visitor accepts, or when the server turned the warning off")
	}
	for _, feature := range []string{"fullscreen=()", "camera=()", "clipboard-write=()", "geolocation=()"} {
		if !strings.Contains(permissionsPolicy, feature) {
			t.Errorf("Permissions-Policy lacks %s", feature)
		}
	}
}

func TestTheSharedPageCannotLeaveForAnotherHost(t *testing.T) {
	if !strings.Contains(shellContentSecurityPolicy, "frame-src 'none'") || strings.Contains(shellContentSecurityPolicy, "frame-src blob:") {
		t.Fatalf("the shell must refuse every frame navigation: %q", shellContentSecurityPolicy)
	}
	shell, err := fs.ReadFile(shareshell.Files, "shell.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(shell)
	for _, want := range []string{"connect-src 'none'", "form-action 'none'", "base-uri 'none'"} {
		if !strings.Contains(js, want) {
			t.Errorf("the artifact policy lacks %s", want)
		}
	}
	if !strings.Contains(js, "sandbox: 'allow-scripts',") {
		t.Error("the sandbox token list must be exactly allow-scripts")
	}
	for _, banned := range []string{"allow-top-navigation", "allow-popups", "allow-forms", "allow-downloads", "allow-modals", "allow-pointer-lock", "allow-same-origin", "allow-presentation", "allow-orientation-lock"} {
		if strings.Contains(js, banned) {
			t.Errorf("the sandbox grants %s", banned)
		}
	}
	for _, want := range []string{
		"event.source !== artifactFrame.contentWindow",
		"value.length > MAX_LINK_LENGTH",
		"'http:'",
		"'https:'",
		"url.username || url.password",
		"This link leaves the shared page: ${url.host}",
		"window.open(url.href, '_blank', 'noopener,noreferrer')",
		"const MAX_LINK_LENGTH = 2048",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("shell.js lacks %q", want)
		}
	}
	if strings.Count(js, "window.open(") != 1 || strings.Contains(js, "location.href =") || strings.Contains(js, "location.assign") || strings.Contains(js, "location.replace") {
		t.Error("the only navigation the shell performs is the confirmed window.open")
	}
}
