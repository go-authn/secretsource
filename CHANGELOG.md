# Changelog

## v0.5.1

Security audit 2026-11-21.

- `keepassxc:` (Unix): the socket is refused when it is a symbolic link, or when its
  directory is owned by another user or writable by group or others (on Linux the
  fallback is `/tmp/runtime-$USER`, which anyone can pre-create), and the connected
  peer's uid is checked after the dial (`SO_PEERCRED`, `LOCAL_PEERCRED`; macOS and
  Linux), so a path re-pointed between the check and the dial is caught. The legacy
  `$XDG_RUNTIME_DIR/org.keepassxc.KeePassXC.BrowserServer` symlink is no longer
  followed; the real socket under `app/org.keepassxc.KeePassXC/` is.
- `file:` on a FIFO no longer blocks past the context: the file is opened with
  `O_NONBLOCK` and refused as not a regular file.
- `file:` holding nothing (or only a line ending) is refused with `ErrEmpty`, like
  every other backend, instead of returning an empty secret: a truncated password
  file used to become an empty PIN. Behaviour change.

## v0.5.0

- `store` writes `secretservice:KEY=VALUE[,...]` (go-freedesktop/secretservice v0.4.0
  `SetByAttributes`): an existing match is refused unless `--replace`.

## v0.4.0

- `secretsource store REF [--group G] [--login L] [--replace] [--generate N]` and the library
  `Store(ctx, ref, secret, StoreOptions)` / `Generate(n)`: write a secret into `keychain:`,
  `secretservice:SERVICE/ACCOUNT` or `keepassxc:URL` (browser protocol `set-login`: the entry
  carries the URL by construction; duplicate check by URL; `--replace` updates that entry by its
  uuid; several matches are refused and named). `file:` and `secretservice:KEY=VALUE` are refused.
  The secret is typed twice with echo off or read from stdin, never from argv or the environment.
  `--title` is refused for KeePassXC: 2.8.0 ignores it.
- New errors `ErrExists`, `ErrNoStore`. The "no scheme" hint lists `keepassxc:`.
- `FuzzResolveGroup` (the get-database-groups tree) with committed corpus.

## v0.3.1

- Fix: `secretsource check` printed `secretsource: secretsource: bad reference ...`
  (the library's errors already carry the prefix).
- The container reproduction of the KeePassXC 2.8.0 crash is a Go program
  (`repro/keepassxc-2.8.0-crash/kpxrepro`, tested) instead of shell scripts; the
  upstream report notes that the crash is keepassxreboot/keepassxc#13865.

## v0.3.0

- **Fix: v0.2.0 could crash KeePassXC.** `keepassxc:by-uuid/...` and
  `keepassxc:by-path/...` asked KeePassXC for `keepassxc://by-uuid/...` and
  `keepassxc://by-path/...`; KeePassXC 2.8.0 dereferences the end of an empty
  list (`BrowserService::sortPriority`, BrowserService.cpp:1347, via
  `sortEntries`/`findEntries`/`handleGetLogins`) when that lookup finds an entry
  with no URL, and dies with SIGSEGV. Reproduced under gdb on a throwaway
  KeePassXC 2.8.0 built from the tag (`repro/keepassxc-2.8.0-crash/`). Those two
  forms are now refused (`ErrBadRef`) before any connection; use
  `keepassxc:URL` and give the entry that URL (an entry found by its URL has one).
  Breaking for the v0.2.0 forms (below v1: minor).
- A fake KeePassXC in the tests models the crash; the old request is replayed and
  shown to kill it, the new client never sends it.

## v0.2.0

- `keepassxc:by-uuid/HEX`, `keepassxc:by-path/Group/Title`, `keepassxc:URL`: read an entry
  through KeePassXC's browser-integration protocol (NaCl box over its Unix
  socket; macOS and Linux; Windows named pipe not yet). `Associate` and
  `secretsource keepassxc associate` register the machine once, approved in
  KeePassXC; the association is kept in the Keychain (macOS), the Secret Service
  (Linux) or a 0600 file. A lookup never creates trust (`ErrNotAssociated`).
- `secretservice:KEY=VALUE[,KEY=VALUE...]` reads an item by arbitrary attributes
  (go-freedesktop/secretservice v0.3.0 `GetByAttributes`); several matches are
  `ErrAmbiguous`. `secretservice:SERVICE/ACCOUNT` is unchanged, but a value
  containing `=` is now read as attributes.
- `cmd/secretsource`: `keepassxc associate`, `check REF` (never prints a secret).
- New errors `ErrAmbiguous`, `ErrNotAssociated`, `ErrDenied`; `Ref.Entry`, `Ref.Attrs`.
- Fuzz corpora committed for `FuzzParse` and `FuzzDecodeFrame`.

## v0.1.0

- `Open(ctx, ref)` and `Parse(ref)`; schemes `file:`, `keychain:`, `secretservice:`.
- No command scheme; no scheme guessing; 4096-byte bound; context/2-minute timeout.
