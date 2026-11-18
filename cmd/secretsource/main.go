// Command secretsource sets up and checks the references that fido and theca
// read their secrets from (--pin-from, --password-from, --recovery-from).
//
//	secretsource keepassxc associate   # once: approve this machine in KeePassXC
//	secretsource check REF             # resolve REF, say whether it worked, print nothing secret
//
// It never prints a secret.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/go-authn/secretsource"
)

// The library calls, replaceable by tests.
var (
	associate = secretsource.Associate
	open      = secretsource.Open
	osExit    = os.Exit
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	root := RootCmd()
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(root.ErrOrStderr(), "secretsource:", err)
		stop()
		osExit(1)
	}
}

// RootCmd builds the command tree.
func RootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "secretsource",
		Short:         "Set up and check secret references (file:, keychain:, secretservice:, keepassxc:)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	kp := &cobra.Command{Use: "keepassxc", Short: "KeePassXC browser integration"}
	kp.AddCommand(&cobra.Command{
		Use:   "associate",
		Short: "Register this machine with the database open in KeePassXC (once)",
		Long: "Asks KeePassXC to associate this machine with the open database. KeePassXC\n" +
			"shows a dialog: name the connection (for example \"laptop\") and accept. The\n" +
			"association is kept in the macOS Keychain, the Secret Service on Linux, or a\n" +
			"0600 file in the configuration directory. Browser Integration must be enabled\n" +
			"in KeePassXC (Settings > Browser Integration > Enable browser integration).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "Approve the association in KeePassXC...")
			a, err := associate(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Associated as %q with database %s.\n", a.ID, a.Database)
			return nil
		},
	})
	root.AddCommand(kp, &cobra.Command{
		Use:   "check REF",
		Short: "Resolve a reference and say whether it worked (never prints the secret)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := open(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			defer s.Close()
			fmt.Fprintf(cmd.OutOrStdout(), "ok: %s holds %d bytes.\n", args[0], len(s.Bytes()))
			return nil
		},
	})
	return root
}
