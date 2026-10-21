package adminweb

import "embed"

//go:embed *.html admin.css admin.js
var Files embed.FS
