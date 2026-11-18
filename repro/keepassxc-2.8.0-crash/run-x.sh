#!/bin/sh
# Throwaway KeePassXC 2.8.0 on an open Xvfb (so a dialog can be answered by xdotool) under gdb, database unlocked.
export HOME=/root XDG_RUNTIME_DIR=/tmp/xdg QT_QPA_PLATFORM=xcb DISPLAY=:99
rm -f /w/gdb-x.log
Xvfb :99 -ac -screen 0 1280x800x24 > /w/xvfb.log 2>&1 &
sleep 2
exec dbus-run-session -- \
  gdb -batch -ex 'handle SIGPIPE nostop noprint pass' -ex run -ex bt -ex 'info registers pc' -ex 'x/3i $pc' \
  --args /build/src/keepassxc --pw-stdin /root/t.kdbx < /root/pw.txt > /w/gdb-x.log 2>&1
