package app

import "os"

func openImportFile(path string) (*os.File, error) { return os.Open(path) }
