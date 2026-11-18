# Reproducing the KeePassXC 2.8.0 crash

Everything runs in a container on a throwaway database; nothing touches a real KeePassXC.
The driver is `kpxrepro` (Go, its own module, tested), run from this folder:

```sh
go run ./kpxrepro build          # docker build, probe.test and kpxrepro-linux for linux
go run ./kpxrepro up             # start the container
go run ./kpxrepro setup          # database t.kdbx, one entry "Yubikey PIN" WITHOUT a URL
go run ./kpxrepro run 'keepassxc://by-path/Yubikey PIN'   # gdb: SIGSEGV in BrowserService::sortPriority
go run ./kpxrepro seturl         # give the entries URLs
go run ./kpxrepro run 'https://theca.invalid/vault'       # 1 entry, no crash
go run ./kpxrepro down
```

`run` starts KeePassXC on an Xvfb under gdb, replays `probe_test.go` (build tag `probe`: the client
of this repository, change-public-keys, get-databasehash, associate, get-logins), answers the two
KeePassXC dialogs with `xdotool`, and prints the probe log and the gdb signal, frame 0 and
faulting instruction. It was written for an arm64 host (`GOARCH` follows the host).

The upstream report is [UPSTREAM-REPORT.md](UPSTREAM-REPORT.md); the issue is
keepassxreboot/keepassxc#13865.
