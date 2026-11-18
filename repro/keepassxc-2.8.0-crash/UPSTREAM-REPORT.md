# DRAFT, not filed. KeePassXC asks for security reports privately; the owner decides.

## KeePassXC 2.8.0 (and current develop): browser-integration `get-logins` crashes with SIGSEGV when a `keepassxc://by-uuid/` or `keepassxc://by-path/` lookup finds an entry that has no URL

**Affected:** 2.8.0 (tag `2.8.0`, commit `1c2f23ef5914c0f442a00533def1689857afb5a7`), macOS arm64 release
build and a Linux/aarch64 build from the tag; the same line is present on `develop` as of 2026-11-17
(`src/browser/BrowserService.cpp:1367` there).

**Effect:** KeePassXC terminates (EXC_BAD_ACCESS / SIGSEGV, null read, main thread). Data is not read or
modified; the unsaved state of the open database is lost with the process.

**Who can trigger it:** any client that has completed the browser-integration association (the user
accepts one dialog), or that holds a previously stored association id and key. It is not reachable before
association: `handleGetLogins` returns error 8 when `!m_associated` (BrowserAction.cpp:223).

### Cause (2.8.0 source)

`BrowserService::shouldIncludeEntry` accepts an entry **without looking at its URLs** when the requested URL
starts with `keepassxc://by-uuid/` or `keepassxc://by-path/` (BrowserService.cpp:1375-1378 in 2.8.0).
The entry is then allowed (or confirmed) and handed to `sortEntries` (BrowserService.cpp:1134), which calls
`sortPriority(entry->getAllUrls(), ...)`. For an entry with an empty URL field and no additional URLs,
`getAllUrls()` is empty (Entry.cpp:402-412), the `for (const auto& entryUrl : urls)` loop adds nothing, and

```cpp
return *std::max_element(priorityList.begin(), priorityList.end());   // BrowserService.cpp:1347
```

dereferences `end()` of an empty `QList<int>` (null data pointer).

gdb on the 2.8.0 tag (RelWithDebInfo):

```
Thread 1 "keepassxc" received signal SIGSEGV, Segmentation fault.
#0  BrowserService::sortPriority (urls=..., ...) at src/browser/BrowserService.cpp:1347
#1  BrowserService::sortEntries (...)            at src/browser/BrowserService.cpp:1134
#2  BrowserService::findEntries (...)            at src/browser/BrowserService.cpp:444
#3  BrowserAction::handleGetLogins (...)        at src/browser/BrowserAction.cpp:251
#4  BrowserAction::handleAction (...)           at src/browser/BrowserAction.cpp:92
#5  BrowserAction::processClientMessage (...)   at src/browser/BrowserAction.cpp:73
#6  BrowserService::processClientMessage (...)  at src/browser/BrowserService.cpp:1787
#8  BrowserHost::clientMessageReceived / #9 BrowserHost::readProxyMessage (BrowserHost.cpp:87)
=> ldr w19, [x21]      (x21 == 0)
```

The macOS crash report of the release build shows the same nine frames below the socket read and the
faulting instruction `ldr w19, [x19]` right after an inlined `std::max_element` loop.

### Minimal reproduction

1. Database with one entry titled `Yubikey PIN`, URL field empty. Browser Integration enabled.
2. Over the browser socket: `change-public-keys`; `get-databasehash`; `associate` (accept the dialog,
   name it `x`); then an encrypted `get-logins` whose inner message is

```json
{"action":"get-logins","url":"keepassxc://by-path/Yubikey PIN","keys":[{"id":"x","key":"<the idKey sent in associate>"}]}
```

(Allow the entry in the access dialog if it appears; with "always allow" it is not shown.)

3. KeePassXC dies. With the entry's URL set to `https://theca.invalid/vault` the same request returns the
entry and nothing crashes.

`repro/keepassxc-2.8.0-crash/` in go-authn/secretsource reproduces this end to end in a container.

### Suggested fix

Guard the empty list in `sortPriority`: `return priorityList.isEmpty() ? 0 : *std::max_element(...)`, or make
`shouldIncludeEntry` for the `by-uuid` / `by-path` forms keep working but let `sortEntries` treat an entry
with no URL as priority 0. A regression test: `get-logins` with `keepassxc://by-uuid/<uuid>` for an entry whose
URL is empty.
