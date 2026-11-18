package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fake records every program and answers from a handler.
type fake struct {
	calls   []spec
	handler func(spec) (string, error)
	// startErr fails the Start of the named program.
	startErr map[string]error
	// files written by Start (what the program "printed" to its Out file).
	files map[string]string
}

func (f *fake) Output(s spec) (string, error) {
	f.calls = append(f.calls, s)
	if f.handler != nil {
		return f.handler(s)
	}
	return "", nil
}

func (f *fake) Start(s spec) (func() error, error) {
	f.calls = append(f.calls, s)
	if err := f.startErr[filepath.Base(s.Name)]; err != nil {
		return nil, err
	}
	if s.Out != "" {
		if c, ok := f.files[filepath.Base(s.Out)]; ok {
			_ = os.WriteFile(s.Out, []byte(c), 0o644)
		}
	}
	return func() error { return nil }, nil
}

func (f *fake) names() string {
	var n []string
	for _, c := range f.calls {
		n = append(n, c.Name+" "+strings.Join(c.Args, " "))
	}
	return strings.Join(n, "\n")
}

func install(t *testing.T, f *fake) *bytes.Buffer {
	t.Helper()
	oldRun, oldSleep, oldOut := run, sleep, out
	var b bytes.Buffer
	run, sleep, out = f, func(time.Duration) {}, &b
	oldRoot, oldXDG, oldWork := rootDir, xdgDir, workDir
	d := t.TempDir()
	rootDir, xdgDir, workDir = filepath.Join(d, "root"), filepath.Join(d, "xdg"), filepath.Join(d, "w")
	for _, p := range []string{rootDir, workDir} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		run, sleep, out = oldRun, oldSleep, oldOut
		rootDir, xdgDir, workDir = oldRoot, oldXDG, oldWork
	})
	return &b
}

func exec(t *testing.T, args ...string) error {
	t.Helper()
	c := RootCmd()
	c.SetArgs(args)
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	return c.Execute()
}

func TestBuildUpDown(t *testing.T) {
	f := &fake{}
	install(t, f)
	dir := t.TempDir()
	if err := exec(t, "--dir", dir, "build"); err != nil {
		t.Fatal(err)
	}
	if got := f.names(); !strings.Contains(got, "docker build -t kpx280") || !strings.Contains(got, "-tags probe -c") || !strings.Contains(got, "kpxrepro-linux") {
		t.Errorf("build:\n%s", got)
	}
	f.calls = nil
	if err := exec(t, "--dir", dir, "up"); err != nil {
		t.Fatal(err)
	}
	if got := f.names(); !strings.Contains(got, "docker rm -f kpx") || !strings.Contains(got, "docker run -d --name kpx") || !strings.Contains(got, ":/w kpx280 sleep infinity") {
		t.Errorf("up:\n%s", got)
	}
	f.calls = nil
	if err := exec(t, "down"); err != nil || !strings.Contains(f.names(), "docker rm -f kpx") {
		t.Errorf("down: %v\n%s", err, f.names())
	}
	// Each failing step is reported with its output.
	for n := 1; n <= 3; n++ {
		count := 0
		f := &fake{handler: func(spec) (string, error) {
			count++
			if count == n {
				return "boom output", errors.New("exit 1")
			}
			return "", nil
		}}
		install(t, f)
		if err := exec(t, "--dir", dir, "build"); err == nil || !strings.Contains(err.Error(), "boom output") {
			t.Errorf("build step %d: %v", n, err)
		}
	}
	f2 := &fake{handler: func(s spec) (string, error) {
		if len(s.Args) > 0 && s.Args[0] == "run" {
			return "no space", errors.New("exit 125")
		}
		return "", nil
	}}
	install(t, f2)
	if err := exec(t, "--dir", dir, "up"); err == nil || !strings.Contains(err.Error(), "no space") {
		t.Errorf("up failing: %v", err)
	}
}

func TestInContainerCommands(t *testing.T) {
	f := &fake{handler: func(spec) (string, error) { return "inside output\n", nil }}
	b := install(t, f)
	for _, c := range [][]string{{"setup"}, {"seturl"}, {"run", "https://x.invalid/y"}} {
		if err := exec(t, c...); err != nil {
			t.Fatal(c, err)
		}
	}
	got := f.names()
	for _, want := range []string{"docker exec kpx /w/kpxrepro-linux in setup", "in seturl", "in try https://x.invalid/y"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	if !strings.Contains(b.String(), "inside output") {
		t.Error("the container's output is shown")
	}
	f.handler = func(spec) (string, error) { return "", errors.New("exit 1") }
	if err := exec(t, "setup"); err == nil {
		t.Error("a failing container command must fail")
	}
}

func TestSetup(t *testing.T) {
	f := &fake{}
	install(t, f)
	if err := exec(t, "in", "setup"); err != nil {
		t.Fatal(err)
	}
	ini, err := os.ReadFile(filepath.Join(rootDir, ".config", "keepassxc", "keepassxc.ini"))
	if err != nil || !strings.Contains(string(ini), "Enabled=true") {
		t.Fatalf("%v %q", err, ini)
	}
	if pw, _ := os.ReadFile(filepath.Join(rootDir, "pw.txt")); string(pw) != "pw\n" {
		t.Errorf("pw.txt %q", pw)
	}
	if got := f.names(); !strings.Contains(got, "db-create -p") || !strings.Contains(got, "add -p") || strings.Contains(got, "--url") {
		t.Errorf("the throwaway entry must have no URL:\n%s", got)
	}
	if f.calls[0].Stdin != "pw\npw\n" {
		t.Errorf("stdin %q", f.calls[0].Stdin)
	}
	// Each failing step.
	for n := 1; n <= 2; n++ {
		count := 0
		f := &fake{handler: func(spec) (string, error) {
			count++
			if count == n {
				return "", errors.New("exit 1")
			}
			return "", nil
		}}
		install(t, f)
		if err := exec(t, "in", "setup"); err == nil {
			t.Errorf("cli call %d failing", n)
		}
	}
	// File-system failures.
	install(t, &fake{})
	os.WriteFile(xdgDir, nil, 0o600) // a file where the runtime dir goes
	if err := setup(); err == nil {
		t.Error("xdg dir")
	}
	install(t, &fake{})
	os.WriteFile(filepath.Join(rootDir, ".config"), nil, 0o600)
	if err := setup(); err == nil {
		t.Error("config dir")
	}
	install(t, &fake{})
	os.MkdirAll(filepath.Join(rootDir, ".config", "keepassxc", "keepassxc.ini"), 0o755)
	if err := setup(); err == nil {
		t.Error("ini is a directory")
	}
	install(t, &fake{})
	os.MkdirAll(filepath.Join(rootDir, "pw.txt"), 0o755)
	if err := setup(); err == nil {
		t.Error("pw.txt is a directory")
	}
}

func TestSetURL(t *testing.T) {
	f := &fake{}
	install(t, f)
	if err := exec(t, "in", "seturl"); err != nil {
		t.Fatal(err)
	}
	got := f.names()
	for _, want := range []string{"pkill -f /build/src/keepassxc", "pkill Xvfb", "edit -q --url https://theca.invalid/vault", "--url theca://vault"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	for n := 3; n <= 4; n++ {
		count := 0
		f := &fake{handler: func(spec) (string, error) {
			count++
			if count == n {
				return "", errors.New("exit 1")
			}
			return "", nil
		}}
		install(t, f)
		if err := setURL(); err == nil {
			t.Errorf("call %d failing", n)
		}
	}
}

func TestAnswer(t *testing.T) {
	f := &fake{handler: func(s spec) (string, error) {
		if s.Args[0] == "search" {
			return "4242\n", nil
		}
		return "", nil
	}}
	b := install(t, f)
	if err := answer("New key association request", "probe1"); err != nil {
		t.Fatal(err)
	}
	got := f.names()
	if !strings.Contains(got, "windowfocus 4242") || !strings.Contains(got, "type --delay 50 probe1") || !strings.Contains(got, "key Return") || !strings.Contains(b.String(), "answered") {
		t.Errorf("%s", got)
	}
	f.calls = nil
	if err := answer("Browser Access Request", ""); err != nil || strings.Contains(f.names(), "xdotool type") {
		t.Errorf("no text: %v\n%s", err, f.names())
	}
	// Never shown: gives up after 40 tries.
	f = &fake{}
	install(t, f)
	if err := answer("Nothing", ""); err == nil || len(f.calls) != 40 {
		t.Errorf("%v after %d searches", err, len(f.calls))
	}
	// The key press fails.
	f = &fake{handler: func(s spec) (string, error) {
		if s.Args[0] == "key" {
			return "", errors.New("exit 1")
		}
		return "7\n", nil
	}}
	install(t, f)
	if err := answer("x", ""); err == nil {
		t.Error("key failure")
	}
}

const probeLog = "=== RUN TestProbe\n    probe_test.go:62: get-logins: x (0 entries)\n"
const gdbLog = "Thread 1 received signal SIGSEGV, Segmentation fault.\n#0  BrowserService::sortPriority () at BrowserService.cpp:1347\n#1  sortEntries\n=> 0x1: ldr w19, [x21]\nnoise\n"

func TestTryReportsTheCrash(t *testing.T) {
	f := &fake{files: map[string]string{"probe.log": probeLog, "gdb-x.log": gdbLog}, handler: func(s spec) (string, error) {
		if s.Name == "xdotool" && s.Args[0] == "search" {
			return "99\n", nil
		}
		return "", nil
	}}
	b := install(t, f)
	pw := filepath.Join(rootDir, "pw.txt")
	os.WriteFile(pw, []byte("pw\n"), 0o600)
	if err := exec(t, "in", "try", "keepassxc://by-path/Yubikey PIN"); err != nil {
		t.Fatal(err)
	}
	var gdb, probe *spec
	for i := range f.calls {
		c := &f.calls[i]
		if c.Name == "dbus-run-session" {
			gdb = c
		}
		if filepath.Base(c.Name) == "probe.test" {
			probe = c
		}
	}
	if gdb == nil || gdb.Stdin != "pw\n" || !strings.Contains(strings.Join(gdb.Args, " "), "--pw-stdin") {
		t.Fatalf("gdb: %+v", gdb)
	}
	if probe == nil || !strings.Contains(strings.Join(probe.Env, " "), "KPX_URL=keepassxc://by-path/Yubikey PIN") || !strings.Contains(strings.Join(probe.Env, " "), "KPX_STEP=5") {
		t.Fatalf("probe: %+v", probe)
	}
	o := b.String()
	for _, want := range []string{"--- probe.log", "get-logins: x (0 entries)", "SIGSEGV", "#0  BrowserService::sortPriority", "=> 0x1"} {
		if !strings.Contains(o, want) {
			t.Errorf("report lacks %q:\n%s", want, o)
		}
	}
	if strings.Contains(o, "noise") {
		t.Error("the gdb log is filtered to the signal, frame 0 and the instruction")
	}
}

func TestTryFailures(t *testing.T) {
	boot := func(f *fake) {
		install(t, f)
		os.WriteFile(filepath.Join(rootDir, "pw.txt"), []byte("pw\n"), 0o600)
	}
	for _, name := range []string{"Xvfb", "dbus-run-session", "probe.test"} {
		f := &fake{startErr: map[string]error{name: errors.New("no such program")}}
		boot(f)
		if err := try("u://x"); err == nil {
			t.Errorf("%s failing to start", name)
		}
	}
	// The association dialog never appears.
	boot(&fake{})
	if err := try("u://x"); err == nil || !strings.Contains(err.Error(), "association") {
		t.Errorf("no dialog: %v", err)
	}
	// Logs missing: the report fails.
	f := &fake{handler: func(s spec) (string, error) {
		if s.Name == "xdotool" && s.Args[0] == "search" {
			return "1\n", nil
		}
		return "", nil
	}}
	boot(f)
	if err := try("u://x"); err == nil {
		t.Error("missing logs")
	}
	f = &fake{files: map[string]string{"probe.log": "x"}, handler: f.handler}
	boot(f)
	if err := try("u://x"); err == nil {
		t.Error("missing gdb log")
	}
}

func TestExecRunner(t *testing.T) {
	r := execRunner{}
	if o, err := r.Output(spec{Name: "cat", Stdin: "hello"}); err != nil || o != "hello" {
		t.Errorf("%q %v", o, err)
	}
	if _, err := r.Output(spec{Name: "sh", Args: []string{"-c", "exit 3"}}); err == nil {
		t.Error("a failing program fails")
	}
	f := filepath.Join(t.TempDir(), "out.txt")
	if _, err := r.Output(spec{Name: "sh", Args: []string{"-c", "echo $KPX_T"}, Env: []string{"KPX_T=env-ok"}, Out: f}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(f); string(b) != "env-ok\n" {
		t.Errorf("%q", b)
	}
	if _, err := r.Output(spec{Name: "true", Out: filepath.Join(t.TempDir(), "missing", "x")}); err == nil {
		t.Error("cannot create the output file")
	}
	if _, err := r.Start(spec{Name: "true", Out: filepath.Join(t.TempDir(), "missing", "x")}); err == nil {
		t.Error("cannot create the output file (start)")
	}
	wait, err := r.Start(spec{Name: "sh", Args: []string{"-c", "echo started"}, Out: f})
	if err != nil || wait() != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(f); string(b) != "started\n" {
		t.Errorf("%q", b)
	}
	wait, err = r.Start(spec{Name: "true"})
	if err != nil || wait() != nil {
		t.Fatal(err)
	}
	if _, err := r.Start(spec{Name: "/nonexistent/program", Out: f}); err == nil {
		t.Error("a missing program (with output file)")
	}
	if _, err := r.Start(spec{Name: "/nonexistent/program"}); err == nil {
		t.Error("a missing program")
	}
}

func TestMain_ExitsOnError(t *testing.T) {
	oldExit, oldArgs := osExit, os.Args
	t.Cleanup(func() { osExit, os.Args = oldExit, oldArgs })
	code := -1
	osExit = func(c int) { code = c }
	os.Args = []string{"kpxrepro", "run"} // a missing argument
	main()
	if code != 1 {
		t.Errorf("exit %d", code)
	}
	code = -1
	os.Args = []string{"kpxrepro", "--help"}
	main()
	if code != -1 {
		t.Errorf("--help exited %d", code)
	}
}
