# secretsource

Resolve a secret (a FIDO2 PIN, a container password, a recovery code) from a
**reference** instead of a plaintext file left on disk.

```go
s, err := secretsource.Open(ctx, "keepassxc:https://fido.invalid/yubikey-5c")
if err != nil { ... }
defer s.Close()          // overwrites the bytes
use(s.Bytes())
```

| Reference | Reads |
|---|---|
| `file:PATH` | a regular file readable by its owner alone (Unix: mode 0600 or stricter; Windows: an access list that grants no read or write right to anyone but the owner, SYSTEM and Administrators); one trailing newline is stripped |
| `keychain:SERVICE/ACCOUNT` | a macOS Keychain generic-password item (pure Go, [go-macos/keychain](https://github.com/go-macos/keychain)) |
| `secretservice:SERVICE/ACCOUNT` | a freedesktop Secret Service item with attributes `service=SERVICE`, `account=ACCOUNT` |
| `secretservice:KEY=VALUE[,KEY=VALUE...]` | the one Secret Service item carrying all those attributes, whatever else it has (a KeePassXC entry exposed by its Secret Service integration: `Title=...`, `UserName=...`; or `secret-tool store`). No escaping: keys and values hold no `,`. Several matches are refused |
| `keepassxc:URL` | the KeePassXC entry whose **URL field** is that URL (any `scheme://host...`; `https://NAME.invalid/...` is a good, never-resolving choice), through KeePassXC's browser-integration protocol. Two entries with the same URL are refused as ambiguous |

`keepassxc:by-uuid/...` and `keepassxc:by-path/...` (KeePassXC's own lookups) are
**refused**: KeePassXC 2.8.0 crashes (SIGSEGV, `BrowserService::sortPriority`,
`std::max_element` of an empty list) when a lookup finds an entry with no URL,
and a PIN entry often has none. Found by URL, an entry has one by construction.

A reference never holds the secret, so it may sit in a flag, a script or a
shell history. There is **no scheme that runs a command**: a flag must never be
able to start a process. A reference with no scheme is refused, not guessed to
be a path (`file:` is how a path is written).

Bounds: a secret longer than 4096 bytes is refused; an empty one from a manager
is refused; a call ends with its context (2 minutes when the context has no
deadline) even when the manager is waiting for you to unlock it, and a late
answer is wiped, never used. Errors are typed: `ErrNotFound`, `ErrAmbiguous`,
`ErrUnavailable` (no manager, locked, unlock dismissed), `ErrNotAssociated`,
`ErrDenied`, `ErrBadRef`, `ErrScheme`, `ErrEmpty`, `ErrTooLarge`. (The Go
runtime keeps a copy of a secret that crossed a JSON string until the garbage
collector reclaims it; the buffers this package owns are wiped.)

## KeePassXC (macOS, Linux)

KeePassXC has no Secret Service on macOS; it does have a browser-integration
socket, which this package speaks as a client: NaCl `crypto_box` over a local
Unix socket (`$TMPDIR`-independent per-user temporary directory on macOS,
`$XDG_RUNTIME_DIR/app/org.keepassxc.KeePassXC/` on Linux), after an association
that you approve once in KeePassXC. Windows (a named pipe) is not implemented
yet. The protocol was read from KeePassXC's `src/browser/` (BrowserHost,
BrowserShared, BrowserAction, BrowserMessageBuilder, BrowserService).

1. In KeePassXC: *Settings > Browser Integration > Enable browser integration*.
   Leave the database open (or let the request unlock it).
2. Associate this machine, once per database:

   ```
   go install github.com/go-authn/secretsource/cmd/secretsource@latest
   secretsource keepassxc associate
   ```

   KeePassXC asks you to name the connection (say `laptop`) and accept. The
   association (that name and an identification public key; no password) is kept
   in the macOS Keychain, in the Secret Service on Linux when one answers, and
   otherwise in a 0600 file under your configuration directory. A lookup never
   creates an association; without one it fails with `ErrNotAssociated`.
3. Create the entry (Title `Yubikey PIN`, Password = the PIN) and **fill its URL
   field** with `https://fido.invalid/yubikey-5c` (any URL not used by another
   entry: the reference is that URL). Then check the reference without printing
   anything:

   ```
   secretsource check 'keepassxc:https://fido.invalid/yubikey-5c'
   ```

   The first read of an entry shows KeePassXC's access dialog: allow it, and
   tick *Remember* to stop being asked.
4. Use it: `fido fingerprint list --pin-from 'keepassxc:https://fido.invalid/yubikey-5c'`.

KeePassXC answers whichever database is open; with a locked database it opens
its unlock dialog and waits for you (up to the 2-minute bound).

## Storing a secret: `secretsource store`

No entry has to be made by hand:

```sh
secretsource store 'keepassxc:https://fido.invalid/yubikey-5c'        # typed twice, echo off
secretsource store 'keepassxc:https://fido.invalid/yubikey-5c' --generate 24   # draws 24 letters and digits, prints nothing secret
printf '%s' "$PIN" | secretsource store keychain:fido/yubikey-5c       # from stdin when it is not a terminal
```

The secret is never taken from an argument or the environment. An existing entry is refused
unless `--replace` (for KeePassXC that updates *that* entry, found by its URL, in place).
`keychain:`, `secretservice:SERVICE/ACCOUNT` and `secretservice:KEY=VALUE[,...]` write an item
(the last carries exactly those attributes; to replace one that has more attributes, name them
all, since the Secret Service replaces only an item with the same attributes); `file:` is
refused (no more plaintext files).

For `keepassxc:` it uses the browser protocol's `set-login` (KeePassXC 2.8.0:
`BrowserAction::handleSetLogin`, `BrowserService::addEntry`/`updateEntry`), so the entry always
carries the URL that finds it again. The login defaults to the URL's host (`--login`); 2.8.0 titles
the new entry after that host and ignores a title (BrowserService.cpp:891), so `--title` is refused;
the group is `KeePassXC-Browser Passwords` (created under the root) unless `--group Keys/FIDO`
(names below the root). The duplicate check is a lookup by URL, never by uuid or path. KeePassXC
shows its own dialogs (an access request for the existing entry, an update confirmation) and saves
the database according to its settings.

## Storing a secret by hand

macOS Keychain: `security add-generic-password -s fido -a yubikey-5c -w` (`-w`
last, with no value, asks on the terminal; the secret is not in argv), then
`keychain:fido/yubikey-5c`.

Linux: `secret-tool store --label "yubikey PIN" service fido account yubikey-5c`,
then `secretservice:fido/yubikey-5c`.

Used by `fido --pin-from` ([go-authn/fido](https://github.com/go-authn/fido))
and `theca --pin-from/--password-from/--recovery-from`
([go-theca/theca](https://github.com/go-theca/theca)).

BSD 3-Clause.
