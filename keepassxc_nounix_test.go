//go:build !unix

package secretsource

import "testing"

func checkOwner(*testing.T, string) {}
