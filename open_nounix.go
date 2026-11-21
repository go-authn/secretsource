//go:build !unix

package secretsource

import "os"

func openSecretFile(path string) (*os.File, error) { return os.Open(path) }
