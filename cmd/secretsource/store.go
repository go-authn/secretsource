package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/go-authn/secretsource"
)

// The library calls and the terminal, replaceable by tests.
var (
	store        = secretsource.Store
	generate     = secretsource.Generate
	isTerminal   = term.IsTerminal
	readPassword = term.ReadPassword
)

// readNewSecret reads the secret to store: from the terminal with echo off,
// typed twice, or, when standard input is not a terminal, from it (for scripts).
// Never from an argument or the environment.
func readNewSecret(cmd *cobra.Command) ([]byte, error) {
	in := cmd.InOrStdin()
	if f, ok := in.(*os.File); ok && isTerminal(int(f.Fd())) {
		fd := int(f.Fd())
		fmt.Fprint(cmd.ErrOrStderr(), "Secret to store: ")
		a, err := readPassword(fd)
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return nil, err
		}
		fmt.Fprint(cmd.ErrOrStderr(), "Again: ")
		b, err := readPassword(fd)
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			clear(a)
			return nil, err
		}
		defer clear(b)
		if !bytes.Equal(a, b) {
			clear(a)
			return nil, errors.New("the two entries differ")
		}
		return a, nil
	}
	b, err := io.ReadAll(io.LimitReader(in, secretsource.MaxSize+1))
	if err == nil && len(b) > secretsource.MaxSize {
		err = fmt.Errorf("the secret is longer than %d bytes", secretsource.MaxSize)
	}
	if err != nil {
		clear(b)
		return nil, err
	}
	n := len(b)
	if n > 0 && b[n-1] == '\n' {
		n--
		if n > 0 && b[n-1] == '\r' {
			n--
		}
	}
	return b[:n], nil
}

func storeCmd() *cobra.Command {
	var o secretsource.StoreOptions
	var title string
	var gen int
	cmd := &cobra.Command{
		Use:   "store REF",
		Short: "Store a secret under a reference (keychain:, secretservice:, keepassxc:)",
		Long: "Stores a secret so no plaintext file is needed. The secret is typed twice with\n" +
			"echo off, or read from standard input when that is not a terminal; it is never\n" +
			"taken from an argument or the environment. --generate N draws N random\n" +
			"characters instead and prints nothing secret.\n\n" +
			"  keychain:SERVICE/ACCOUNT       macOS Keychain item\n" +
			"  secretservice:SERVICE/ACCOUNT  Secret Service item\n" +
			"  keepassxc:URL                  KeePassXC entry with that URL (needs `keepassxc associate`);\n" +
			"                                 an existing entry is refused unless --replace\n" +
			"  file:PATH                      refused: no more plaintext files\n\n" +
			"KeePassXC 2.8.0 titles a new entry after the URL's host (it ignores a title in\n" +
			"set-login) and puts it in the group \"KeePassXC-Browser Passwords\" unless --group.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("title") {
				return fmt.Errorf("--title %q: KeePassXC 2.8.0 titles a new entry after the URL's host (BrowserService.cpp:891) and set-login has no title field; rename the entry in KeePassXC", title)
			}
			var secret []byte
			var err error
			if cmd.Flags().Changed("generate") {
				secret, err = generate(gen)
			} else {
				secret, err = readNewSecret(cmd)
			}
			if err != nil {
				return err
			}
			defer clear(secret)
			if err := store(cmd.Context(), args[0], secret, o); err != nil {
				return err
			}
			if cmd.Flags().Changed("generate") {
				fmt.Fprintf(cmd.OutOrStdout(), "Generated %d characters and stored them in %s; nothing was printed.\n", gen, args[0])
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Stored in %s.\n", args[0])
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&title, "title", "", "not supported by KeePassXC 2.8.0 (the entry is titled after the URL's host)")
	cmd.Flags().StringVar(&o.Group, "group", "", "keepassxc: the group of a new entry, names below the root separated by / (default: KeePassXC-Browser Passwords)")
	cmd.Flags().StringVar(&o.Login, "login", "", "keepassxc: the entry's user name (default: the URL's host)")
	cmd.Flags().BoolVar(&o.Replace, "replace", false, "overwrite an existing entry (keepassxc: updates THAT entry in place)")
	cmd.Flags().IntVar(&gen, "generate", 0, "store N random characters (letters and digits) instead of reading a secret")
	return cmd
}
