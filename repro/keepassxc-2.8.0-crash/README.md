# Reproducing the KeePassXC 2.8.0 crash

Everything runs in a container on a throwaway database; nothing touches a real KeePassXC.

```
docker build -t kpx280 .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -tags probe -c -o probe.test ../..   # amd64 on an Intel host
docker run -d --name kpx --cap-add SYS_PTRACE --security-opt seccomp=unconfined -v $PWD:/w kpx280 sleep infinity
docker exec kpx sh /w/setup.sh                       # database t.kdbx, one entry "Yubikey PIN" WITHOUT a URL
docker exec kpx sh /w/try.sh "keepassxc://by-path/Yubikey PIN"   # gdb: SIGSEGV in BrowserService::sortPriority
docker exec kpx sh /w/seturl.sh                      # give the entries URLs
docker exec kpx sh /w/try.sh "https://theca.invalid/vault"       # 1 entry, no crash
```

`try.sh` starts KeePassXC on an Xvfb under gdb, runs `probe_test.go` (the client of
this repository, step 5: change-public-keys, get-databasehash, associate, get-logins),
and answers the two KeePassXC dialogs with `xdotool`.
