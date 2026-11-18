// Command kpxrepro drives the container reproduction of the KeePassXC 2.8.0
// crash (see ../README.md). It runs on the host (build, up, run, down) and, as
// a linux binary mounted into the container, inside it (in setup, in seturl,
// in try). Everything it starts is a throwaway KeePassXC with its own socket
// and database; it never talks to a real one.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	image     = "kpx280"
	container = "kpx"
	mount     = "/w"
	sockPath  = "/tmp/xdg/app/org.keepassxc.KeePassXC/org.keepassxc.KeePassXC.BrowserServer"
	display   = ":99"
)

// Where things live inside the container; tests point them at a temp dir.
var (
	rootDir = "/root"
	xdgDir  = "/tmp/xdg"
	workDir = mount
)

func dbPath() string { return filepath.Join(rootDir, "t.kdbx") }

// spec describes one program to run.
type spec struct {
	Name  string
	Args  []string
	Env   []string
	Stdin string
	// Out, when set, is a file the program's stdout and stderr go to.
	Out string
	Dir string
}

// runner starts programs; tests replace it.
type runner interface {
	// Output runs to completion and returns the combined output.
	Output(spec) (string, error)
	// Start runs in the background and returns the function that waits for it.
	Start(spec) (func() error, error)
}

type execRunner struct{ log io.Writer }

func (r execRunner) cmd(s spec) (*osexec.Cmd, *os.File, error) {
	c := osexec.Command(s.Name, s.Args...)
	c.Env = append(os.Environ(), s.Env...)
	c.Dir = s.Dir
	if s.Stdin != "" {
		c.Stdin = strings.NewReader(s.Stdin)
	}
	if s.Out == "" {
		return c, nil, nil
	}
	f, err := os.Create(s.Out)
	if err != nil {
		return nil, nil, err
	}
	c.Stdout, c.Stderr = f, f
	return c, f, nil
}

func (r execRunner) Output(s spec) (string, error) {
	c, f, err := r.cmd(s)
	if err != nil {
		return "", err
	}
	if f != nil {
		defer f.Close()
		return "", c.Run()
	}
	var b bytes.Buffer
	c.Stdout, c.Stderr = &b, &b
	err = c.Run()
	return b.String(), err
}

func (r execRunner) Start(s spec) (func() error, error) {
	c, f, err := r.cmd(s)
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		if f != nil {
			f.Close()
		}
		return nil, err
	}
	return func() error {
		if f != nil {
			defer f.Close()
		}
		return c.Wait()
	}, nil
}

// The seams.
var (
	run    runner    = execRunner{}
	sleep            = time.Sleep
	out    io.Writer = os.Stdout
	osExit           = os.Exit
)

func main() {
	root := RootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(root.ErrOrStderr(), "kpxrepro:", strings.TrimPrefix(err.Error(), "kpxrepro: "))
		osExit(1)
	}
}

// RootCmd builds the command tree.
func RootCmd() *cobra.Command {
	root := &cobra.Command{Use: "kpxrepro", Short: "Reproduce the KeePassXC 2.8.0 crash in a container", SilenceUsage: true, SilenceErrors: true}
	dir := root.PersistentFlags().String("dir", ".", "this folder (the Dockerfile and the mount)")
	root.AddCommand(
		&cobra.Command{Use: "build", Short: "docker build the image and cross-compile the probe and this program for linux", Args: cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error { return build(*dir) }},
		&cobra.Command{Use: "up", Short: "start the container", Args: cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error { return up(*dir) }},
		&cobra.Command{Use: "down", Short: "remove the container", Args: cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error { _, err := run.Output(docker("rm", "-f", container)); return err }},
		&cobra.Command{Use: "setup", Short: "create the throwaway database (an entry WITHOUT a URL)", Args: cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error { return inContainer("in", "setup") }},
		&cobra.Command{Use: "seturl", Short: "give the entries URLs", Args: cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error { return inContainer("in", "seturl") }},
		&cobra.Command{Use: "run URL", Short: "start KeePassXC under gdb and replay get-logins for URL", Args: cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, a []string) error { return inContainer("in", "try", a[0]) }},
	)
	in := &cobra.Command{Use: "in", Short: "inside the container", Hidden: true}
	in.AddCommand(
		&cobra.Command{Use: "setup", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return setup() }},
		&cobra.Command{Use: "seturl", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return setURL() }},
		&cobra.Command{Use: "try URL", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, a []string) error { return try(a[0]) }},
	)
	root.AddCommand(in)
	return root
}

func docker(args ...string) spec { return spec{Name: "docker", Args: args} }

func say(format string, a ...any) { fmt.Fprintf(out, format+"\n", a...) }

func build(dir string) error {
	abs, _ := filepath.Abs(dir) // fails only when the working directory is gone
	steps := []spec{
		docker("build", "-t", image, dir),
		{Name: "go", Args: []string{"test", "-tags", "probe", "-c", "-o", filepath.Join(abs, "probe.test"), "github.com/go-authn/secretsource"},
			Env: []string{"GOOS=linux", "CGO_ENABLED=0"}, Dir: abs},
		{Name: "go", Args: []string{"build", "-o", filepath.Join(abs, "kpxrepro-linux"), "."},
			Env: []string{"GOOS=linux", "CGO_ENABLED=0"}, Dir: filepath.Join(abs, "kpxrepro")},
	}
	for _, s := range steps {
		if o, err := run.Output(s); err != nil {
			return fmt.Errorf("%s %s: %w\n%s", s.Name, strings.Join(s.Args, " "), err, o)
		}
	}
	return nil
}

func up(dir string) error {
	abs, _ := filepath.Abs(dir)                      // fails only when the working directory is gone
	_, _ = run.Output(docker("rm", "-f", container)) // a leftover one is not an error
	o, err := run.Output(docker("run", "-d", "--name", container, "--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined",
		"-v", abs+":"+mount, image, "sleep", "infinity"))
	if err != nil {
		return fmt.Errorf("docker run: %w\n%s", err, o)
	}
	return nil
}

// inContainer runs this program's linux build inside the container.
func inContainer(args ...string) error {
	o, err := run.Output(docker(append([]string{"exec", container, mount + "/kpxrepro-linux"}, args...)...))
	fmt.Fprint(out, o)
	return err
}

var env = []string{"HOME=/root", "XDG_RUNTIME_DIR=/tmp/xdg"}

func tool(name string, stdin string, args ...string) error {
	o, err := run.Output(spec{Name: name, Args: args, Env: env, Stdin: stdin})
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", name, err, o)
	}
	return nil
}

const kpxcli = "/build/src/cli/keepassxc-cli"

func setup() error {
	if err := os.MkdirAll(xdgDir, 0o700); err != nil {
		return err
	}
	cfg := filepath.Join(rootDir, ".config", "keepassxc")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		return err
	}
	ini := "[General]\nConfigVersion=2\n\n[Browser]\nEnabled=true\nUnlockDatabase=true\n"
	if err := os.WriteFile(filepath.Join(cfg, "keepassxc.ini"), []byte(ini), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(rootDir, "pw.txt"), []byte("pw\n"), 0o600); err != nil {
		return err
	}
	_ = os.Remove(dbPath())
	if err := tool(kpxcli, "pw\npw\n", "db-create", "-p", dbPath()); err != nil {
		return err
	}
	return tool(kpxcli, "pw\n654321\n", "add", "-p", dbPath(), "Yubikey PIN")
}

func setURL() error {
	_, _ = run.Output(spec{Name: "pkill", Args: []string{"-f", "/build/src/keepassxc"}})
	_, _ = run.Output(spec{Name: "pkill", Args: []string{"Xvfb"}})
	sleep(2 * time.Second)
	if err := tool(kpxcli, "pw\n", "edit", "-q", "--url", "https://theca.invalid/vault", dbPath(), "Yubikey PIN"); err != nil {
		return err
	}
	return tool(kpxcli, "pw\n654321\n", "add", "-p", "-q", "--url", "theca://vault", dbPath(), "Second")
}

// xdotool runs xdotool on the throwaway display.
func xdotool(args ...string) (string, error) {
	return run.Output(spec{Name: "xdotool", Args: args, Env: append([]string{"DISPLAY=" + display}, env...)})
}

// answer waits for the window named name and accepts it: types text (if any)
// and presses Return.
func answer(name, text string) error {
	for i := 0; i < 40; i++ {
		ids, _ := xdotool("search", "--name", name)
		if id := strings.Fields(ids); len(id) > 0 {
			_, _ = xdotool("windowfocus", id[0])
			sleep(time.Second)
			if text != "" {
				_, _ = xdotool("type", "--delay", "50", text)
			}
			_, err := xdotool("key", "Return")
			say("answered %s", name)
			return err
		}
		sleep(time.Second)
	}
	return fmt.Errorf("no dialog %q", name)
}

// try starts KeePassXC on an Xvfb under gdb with the database unlocked, replays
// the probe (change-public-keys, get-databasehash, associate, get-logins for
// url) and prints what happened.
func try(url string) error {
	_, _ = run.Output(spec{Name: "pkill", Args: []string{"-f", "/build/src/keepassxc"}})
	_, _ = run.Output(spec{Name: "pkill", Args: []string{"Xvfb"}})
	sleep(2 * time.Second)
	xenv := append([]string{"DISPLAY=" + display, "QT_QPA_PLATFORM=xcb"}, env...)
	if _, err := run.Start(spec{Name: "Xvfb", Args: []string{display, "-ac", "-screen", "0", "1280x800x24"}, Out: filepath.Join(workDir, "xvfb.log")}); err != nil {
		return err
	}
	sleep(2 * time.Second)
	pw, _ := os.ReadFile(filepath.Join(rootDir, "pw.txt"))
	gdb := spec{Name: "dbus-run-session", Env: xenv, Stdin: string(pw), Out: filepath.Join(workDir, "gdb-x.log"),
		Args: []string{"--", "gdb", "-batch", "-ex", "handle SIGPIPE nostop noprint pass", "-ex", "run", "-ex", "bt", "-ex", "info registers pc",
			"--args", "/build/src/keepassxc", "--pw-stdin", dbPath()}}
	if _, err := run.Start(gdb); err != nil {
		return err
	}
	sleep(12 * time.Second)
	_ = answer("Check for updates", "") // the first-run question, not part of the test
	probe, err := run.Start(spec{Name: filepath.Join(workDir, "probe.test"), Args: []string{"-test.run", "TestProbe", "-test.v"}, Out: filepath.Join(workDir, "probe.log"),
		Env: append([]string{"KPX_SOCK=" + sockPath, "KPX_STEP=5", "KPX_URL=" + url}, env...)})
	if err != nil {
		return err
	}
	if err := answer("New key association request", fmt.Sprintf("probe%d", time.Now().Unix())); err != nil {
		return err
	}
	_ = answer("Browser Access Request", "") // absent when KeePassXC died or the entry needs no confirmation
	_ = probe()
	sleep(3 * time.Second)
	return report()
}

func report() error {
	for _, f := range []string{"probe.log", "gdb-x.log"} {
		b, err := os.ReadFile(filepath.Join(workDir, f))
		if err != nil {
			return err
		}
		say("--- %s", f)
		for _, l := range strings.Split(string(b), "\n") {
			if f == "probe.log" || strings.Contains(l, "SIGSEGV") || strings.HasPrefix(l, "#0 ") || strings.HasPrefix(l, "=> ") {
				say("%s", l)
			}
		}
	}
	return nil
}
