// Package secretsource resolves a secret (a FIDO2 PIN, a container password, a
// recovery code) from a REFERENCE instead of a plaintext file the caller has
// to leave on disk.
//
// A reference is "scheme:value":
//
//	file:PATH                    a regular file readable by its owner alone
//	keychain:SERVICE/ACCOUNT     a macOS Keychain generic-password item
//	secretservice:SERVICE/ACCOUNT  a freedesktop Secret Service item whose
//	                             attributes are service=SERVICE, account=ACCOUNT
//	                             (GNOME Keyring, KWallet, KeePassXC with "Secret
//	                             Service Integration" enabled)
//
// There is deliberately no scheme that runs a command: a reference reaches the
// program through a command-line flag, and a flag must never be able to start
// a process. A reference never holds the secret itself, so it may sit in argv,
// a shell history or a script; the secret travels only from the manager to the
// returned [Secret], which the caller wipes with [Secret.Close].
//
//	s, err := secretsource.Open(ctx, "keychain:fido/yubikey-5c")
//	if err != nil { ... }
//	defer s.Close()
//	use(s.Bytes())
//
// Every call is bounded: a secret longer than [MaxSize] is refused, and the
// call ends with the context (or after [Timeout] when the context has no
// deadline) even when the manager is waiting for the person to unlock it.
package secretsource

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// MaxSize is the longest secret accepted, in bytes.
const MaxSize = 4096

// Timeout bounds a call whose context has no deadline. It is generous because
// a manager may be asking the person to unlock it.
const Timeout = 2 * time.Minute

// Sentinel errors, comparable with [errors.Is].
var (
	// ErrBadRef is a reference that does not parse.
	ErrBadRef = errors.New("secretsource: bad reference")
	// ErrScheme is a reference whose scheme is not supported.
	ErrScheme = errors.New("secretsource: unsupported scheme")
	// ErrNotFound means the manager answered and holds no such entry.
	ErrNotFound = errors.New("secretsource: no such entry")
	// ErrUnavailable means no manager could be reached: none running, the
	// wrong platform, or it is locked and refused to ask.
	ErrUnavailable = errors.New("secretsource: secret manager unavailable")
	// ErrEmpty means the entry exists and holds nothing.
	ErrEmpty = errors.New("secretsource: the entry is empty")
	// ErrTooLarge means the secret is longer than [MaxSize].
	ErrTooLarge = errors.New("secretsource: the secret is too long")
)

// Secret is a resolved secret. Its bytes live until [Secret.Close] overwrites
// them.
type Secret struct{ b []byte }

// Bytes returns the secret. The slice is valid until Close.
func (s Secret) Bytes() []byte { return s.b }

// Close overwrites the secret with zeros. It is safe to call twice and never
// fails; it returns an error only to satisfy io.Closer.
func (s Secret) Close() error {
	clear(s.b)
	return nil
}

// Ref is a parsed reference.
type Ref struct {
	// Scheme is "file", "keychain" or "secretservice".
	Scheme string
	// Path is the file path (file scheme).
	Path string
	// Service and Account name the entry (keychain, secretservice).
	Service, Account string
}

// String renders the reference back as written.
func (r Ref) String() string {
	if r.Scheme == "file" {
		return "file:" + r.Path
	}
	return r.Scheme + ":" + r.Service + "/" + r.Account
}

// Parse reads a reference. It never touches a manager. A reference without a
// scheme is refused rather than guessed to be a path: "file:PATH" is how a
// path is written.
func Parse(ref string) (Ref, error) {
	scheme, value, ok := strings.Cut(ref, ":")
	if !ok {
		return Ref{}, fmt.Errorf("%w: %q has no scheme; write file:PATH, keychain:SERVICE/ACCOUNT or secretservice:SERVICE/ACCOUNT", ErrBadRef, clip(ref))
	}
	if value == "" {
		return Ref{}, fmt.Errorf("%w: %q names nothing after the colon", ErrBadRef, clip(ref))
	}
	if hasControl(value) {
		return Ref{}, fmt.Errorf("%w: a control character in the reference", ErrBadRef)
	}
	switch scheme {
	case "file":
		return Ref{Scheme: scheme, Path: value}, nil
	case "keychain", "secretservice":
		svc, acct, ok := strings.Cut(value, "/")
		if !ok || svc == "" || acct == "" {
			return Ref{}, fmt.Errorf("%w: %q: want %s:SERVICE/ACCOUNT", ErrBadRef, clip(ref), scheme)
		}
		return Ref{Scheme: scheme, Service: svc, Account: acct}, nil
	case "keepassxc":
		return Ref{}, fmt.Errorf("%w: keepassxc: is not implemented yet; enable KeePassXC's Secret Service Integration and use secretservice:", ErrScheme)
	}
	return Ref{}, fmt.Errorf("%w: %q (supported: file, keychain, secretservice)", ErrScheme, clip(scheme))
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

// clip keeps a malformed reference short in an error message.
func clip(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}

// Open resolves ref. The returned Secret must be closed.
func Open(ctx context.Context, ref string) (Secret, error) {
	r, err := Parse(ref)
	if err != nil {
		return Secret{}, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, Timeout)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return Secret{}, err
	}
	var b []byte
	switch r.Scheme {
	case "file":
		// The file backend validates itself (trailing newline, permissions).
		b, err = readFile(r.Path)
		if err != nil {
			return Secret{}, err
		}
		return Secret{b}, nil
	case "keychain":
		b, err = call(ctx, func() ([]byte, error) { return keychainGet(r.Service, r.Account) })
		err = mapKeychain(r, err)
	default: // secretservice
		b, err = call(ctx, func() ([]byte, error) { return secretserviceGet(r.Service, r.Account) })
		err = mapSecretService(r, err)
	}
	if err != nil {
		clear(b)
		return Secret{}, err
	}
	return check(r, b)
}

// check applies the bounds every manager answer is held to.
func check(r Ref, b []byte) (Secret, error) {
	if len(b) > MaxSize {
		clear(b)
		return Secret{}, fmt.Errorf("%w: %s holds more than %d bytes", ErrTooLarge, r, MaxSize)
	}
	if len(b) == 0 {
		return Secret{}, fmt.Errorf("%w: %s", ErrEmpty, r)
	}
	return Secret{b}, nil
}

// call runs a manager call that takes no context, and gives up when ctx ends.
// A call still waiting on the manager then finishes in the background; its
// answer is wiped, never used.
func call(ctx context.Context, fn func() ([]byte, error)) ([]byte, error) {
	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		b, err := fn()
		ch <- result{b, err}
	}()
	select {
	case r := <-ch:
		return r.b, r.err
	case <-ctx.Done():
		go func() { clear((<-ch).b) }()
		return nil, fmt.Errorf("%w: gave up waiting for the secret manager (is it locked, waiting for you to unlock it?): %v", ErrUnavailable, ctx.Err())
	}
}
