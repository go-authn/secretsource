# secretsource

Resolve a secret (a FIDO2 PIN, a container password, a recovery code) from a
**reference** instead of a plaintext file left on disk.

```go
s, err := secretsource.Open(ctx, "keychain:fido/yubikey-5c")
if err != nil { ... }
defer s.Close()          // overwrites the bytes
use(s.Bytes())
```

| Reference | Reads |
|---|---|
| `file:PATH` | a regular file readable by its owner alone (mode 0600 or stricter); one trailing newline is stripped |
| `keychain:SERVICE/ACCOUNT` | a macOS Keychain generic-password item (pure Go, [go-macos/keychain](https://github.com/go-macos/keychain)) |
| `secretservice:SERVICE/ACCOUNT` | a freedesktop Secret Service item with attributes `service=SERVICE`, `account=ACCOUNT` ([go-freedesktop/secretservice](https://github.com/go-freedesktop/secretservice)): GNOME Keyring, KWallet, or KeePassXC with *Secret Service Integration* enabled |

A reference never holds the secret, so it may sit in a flag, a script or a
shell history. There is **no scheme that runs a command**: a flag must never be
able to start a process. A reference with no scheme is refused, not guessed to
be a path (`file:` is how a path is written). `keepassxc:` (the browser-integration
protocol) is not implemented yet.

Bounds: a secret longer than 4096 bytes is refused; an empty one from a manager
is refused; a call ends with its context (2 minutes when the context has no
deadline) even when the manager is waiting for you to unlock it, and a late
answer is wiped, never used. Errors are typed: `ErrNotFound`, `ErrUnavailable`
(no manager, locked, unlock dismissed), `ErrBadRef`, `ErrScheme`, `ErrEmpty`,
`ErrTooLarge`.

## Storing the secret

macOS:

```
security add-generic-password -s fido -a yubikey-5c -w
```

(`-w` last, with no value, asks on the terminal; the secret is not in argv.)

Linux (GNOME Keyring, KWallet, KeePassXC):

```
secret-tool store --label "yubikey PIN" service fido account yubikey-5c
```

In KeePassXC, enable *Tools > Settings > Secret Service Integration* and expose
the group that holds the item; the item must carry the attributes `service` and
`account`.

Used by `fido --pin-from` ([go-authn/fido](https://github.com/go-authn/fido))
and `theca --pin-from/--password-from/--recovery-from`
([go-theca/theca](https://github.com/go-theca/theca)).

BSD 3-Clause.
