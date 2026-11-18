#!/bin/sh
# Throwaway database: give the entries URLs (the GUI must be stopped).
set -x
export HOME=/root
printf 'pw\n' | /build/src/cli/keepassxc-cli edit -q --url "https://theca.invalid/vault" /root/t.kdbx "Yubikey PIN"
printf 'pw\n654321\n' | /build/src/cli/keepassxc-cli add -p -q --url "theca://vault" /root/t.kdbx "Second"
printf 'pw\n' | /build/src/cli/keepassxc-cli ls -q /root/t.kdbx
