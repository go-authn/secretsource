# Changelog

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
