#!/bin/sh
# usage: try.sh URL — starts the throwaway KeePassXC, runs probe step 5 for URL, answers the dialogs.
export DISPLAY=:99
pkill -f /build/src/keepassxc; pkill Xvfb; sleep 2
sh /w/run-x.sh &
sleep 12
id=$(xdotool search --name "Check for updates" | head -n 1)
xdotool windowfocus "$id"; sleep 1; xdotool key Escape; sleep 1
KPX_SOCK=/tmp/xdg/app/org.keepassxc.KeePassXC/org.keepassxc.KeePassXC.BrowserServer KPX_STEP=5 KPX_URL="$1" \
  /w/probe.test -test.run TestProbe -test.v > /w/probe.log 2>&1 &
sh /w/answer.sh
sleep 6
echo "--- probe"; cat /w/probe.log
echo "--- alive:"; pgrep -f build/src/keepassxc | wc -l
echo "--- gdb"; grep -n "SIGSEGV\|^#0 " /w/gdb-x.log
