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
	if !strings.Contains(string(shell), `"connect-src 'none'"`) || !strings.Contains(string(shell), "doc.head.prepend(policy)") {
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
		"document.body.prepend(renderBar())",
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
