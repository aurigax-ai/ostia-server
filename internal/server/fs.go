package server

import "os"

const dataDirMode = 0o700

func mkdirAll(dir string) error { return os.MkdirAll(dir, dataDirMode) }
