#!/bin/sh
# Throwaway database + config inside the container. Nothing here touches a real KeePassXC.
set -ex
export HOME=/root XDG_RUNTIME_DIR=/tmp/xdg
mkdir -p "$XDG_RUNTIME_DIR" "$HOME/.config/keepassxc"
chmod 700 "$XDG_RUNTIME_DIR"
cat > "$HOME/.config/keepassxc/keepassxc.ini" <<'EOF'
[General]
ConfigVersion=2

[Browser]
Enabled=true
UnlockDatabase=true
EOF
rm -f /root/t.kdbx
printf 'pw\npw\n' | /build/src/cli/keepassxc-cli db-create -p /root/t.kdbx
printf 'pw\n654321\n' | /build/src/cli/keepassxc-cli add -p /root/t.kdbx "Yubikey PIN"
printf 'pw\n' > /root/pw.txt
ls -la /root
