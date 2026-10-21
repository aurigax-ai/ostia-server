package shareshell

import "embed"

//go:embed index.html shell.js crypto.js shell.css
var Files embed.FS
