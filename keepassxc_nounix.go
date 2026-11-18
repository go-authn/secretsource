//go:build !unix

package secretsource

// checkSocket: no Unix sockets here (KeePassXC on Windows uses a named pipe,
// not implemented yet), so socketCandidates fails before this is reached.
func checkSocket(string) error { return nil }
