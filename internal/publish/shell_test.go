package publish

import (
	"io/fs"
	"strings"
	"testing"

	shareshell "github.com/aurigax-ai/ostia-server/web/share-shell"
)

func TestPublicSharesAreSandboxedWithoutSameOrigin(t *testing.T) {
	if publicContentSecurityPolicy != "sandbox allow-scripts" {
		t.Fatalf("public artifacts must run in an opaque origin: %q", publicContentSecurityPolicy)
	}
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
