// Package secretflag lets a command take a secret by reference.
//
// A secret given as a flag value is visible in `ps` and in
// /proc/<pid>/cmdline. Each secret therefore gets a `--<name>-from <ref>`
// twin resolved through [secretsource.Open] (systemd-creds:, keychain:,
// keepassxc:, file:). The plain `--<name>` flag stays for one minor release,
// deprecated (a warning goes to stderr), and is mutually exclusive with its
// twin.
//
// [AddFrom] and [AddFromList] register only the -from flag, for a secret that
// never had a plain form.
//
// [Add] registers the pair on a cobra command; [AddStd] on a standard
// library [flag.FlagSet]. Both return a [*Binding] to pass to [Resolve]
// once the flags are parsed.
package secretflag

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/go-authn/secretsource"
	"github.com/spf13/cobra"
)

// open is replaced by tests.
var open = func(ctx context.Context, ref string) ([]byte, error) {
	s, err := secretsource.Open(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return append([]byte(nil), s.Bytes()...), nil
}

// Binding ties a secret destination to its --<name>-from twin.
type Binding struct {
	name string
	dst  *string
	ref  string

	// AddFromList only: every --name-from, in order, resolved into list.
	list *[]string
	refs []string

	// Standard-library flag sets only: cobra enforces exclusivity and
	// prints the deprecation itself.
	fs      *flag.FlagSet
	plain   []string // --name and its aliases
	warnOut io.Writer
}

func usageFrom(usage, name string) string {
	return usage + " read from a secret reference, e.g. systemd-creds:" + name
}

// Add registers --name (deprecated, plain value) and --name-from on cmd and
// returns the binding to pass to [Resolve]. The two flags are mutually
// exclusive.
func Add(cmd *cobra.Command, name string, dst *string, usage string) *Binding {
	b := &Binding{name: name, dst: dst}
	f := cmd.Flags()
	f.StringVar(dst, name, "", usage+" (DEPRECATED: visible in ps; use --"+name+"-from)")
	_ = f.MarkDeprecated(name, "the value is visible in `ps` and /proc/PID/cmdline; use --"+name+"-from <ref> (systemd-creds:, keychain:, keepassxc:, file:)")
	f.StringVar(&b.ref, name+"-from", "", usageFrom(usage, name))
	cmd.MarkFlagsMutuallyExclusive(name, name+"-from")
	return b
}

// AddFrom registers only --name-from, for a secret born after the plain flag
// was deprecated: there is no --name twin whose value would show in ps.
func AddFrom(cmd *cobra.Command, name string, dst *string, usage string) *Binding {
	b := &Binding{name: name, dst: dst}
	cmd.Flags().StringVar(&b.ref, name+"-from", "", usageFrom(usage, name))
	return b
}

// AddFromList registers a repeatable --name-from, with no plain twin; [Resolve]
// appends every resolved secret to dst, in command-line order.
func AddFromList(cmd *cobra.Command, name string, dst *[]string, usage string) *Binding {
	b := &Binding{name: name, list: dst}
	cmd.Flags().StringArrayVar(&b.refs, name+"-from", nil, usage+" (repeatable) read from a secret reference, e.g. systemd-creds:"+name)
	return b
}

// readRef opens ref and returns the secret without trailing newlines.
func readRef(ctx context.Context, name, ref string) (string, error) {
	raw, err := open(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("--%s-from: %w", name, err)
	}
	v := strings.TrimRight(string(raw), "\r\n")
	clear(raw)
	if v == "" {
		return "", fmt.Errorf("--%s-from: %w", name, errEmpty)
	}
	return v, nil
}

// AddStd registers -name (deprecated, plain value, plus any aliases such as
// "t") and -name-from on a standard-library flag set. [Resolve] refuses the
// two together and, when only the plain flag was given, writes the
// deprecation warning to warn (nil means discard).
func AddStd(fs *flag.FlagSet, warn io.Writer, name string, dst *string, usage string, aliases ...string) *Binding {
	if warn == nil {
		warn = io.Discard
	}
	b := &Binding{name: name, dst: dst, fs: fs, warnOut: warn, plain: append([]string{name}, aliases...)}
	plainUsage := usage + " (DEPRECATED: visible in ps; use --" + name + "-from)"
	fs.StringVar(dst, name, "", plainUsage)
	for _, a := range aliases {
		fs.StringVar(dst, a, "", plainUsage)
	}
	fs.StringVar(&b.ref, name+"-from", "", usageFrom(usage, name))
	return b
}

// plainGiven reports whether the plain flag (or an alias) was set on the
// command line of a standard-library flag set.
func (b *Binding) plainGiven() (string, bool) {
	var hit string
	b.fs.Visit(func(f *flag.Flag) {
		for _, p := range b.plain {
			if f.Name == p && hit == "" {
				hit = p
			}
		}
	})
	return hit, hit != ""
}

// Resolve reads every binding whose --<name>-from was given and stores the
// secret in its destination, trimming trailing newlines. A reference that
// resolves to nothing is an error.
func Resolve(ctx context.Context, bs ...*Binding) error {
	for _, b := range bs {
		if b.fs != nil {
			if p, ok := b.plainGiven(); ok {
				if b.ref != "" {
					return fmt.Errorf("--%s-from and --%s are mutually exclusive", b.name, p)
				}
				fmt.Fprintf(b.warnOut, "--%s is deprecated: the value is visible in ps; use --%s-from <ref>\n", p, b.name)
			}
		}
		if b.list != nil {
			for _, r := range b.refs {
				v, err := readRef(ctx, b.name, r)
				if err != nil {
					return err
				}
				*b.list = append(*b.list, v)
			}
			continue
		}
		if b.ref == "" {
			continue
		}
		v, err := readRef(ctx, b.name, b.ref)
		if err != nil {
			return err
		}
		*b.dst = v
	}
	return nil
}

var errEmpty = errors.New("the secret is empty")
