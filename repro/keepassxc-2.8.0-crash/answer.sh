#!/bin/sh
# Accepts the dialogs of the throwaway KeePassXC: the association request (a name + Return),
# then the browser access request (Return = Allow Selected).
export DISPLAY=${DISPLAY:-:99}
answer() {
  for i in $(seq 1 40); do
    id=$(xdotool search --name "$1" 2>/dev/null | head -n 1)
    if [ -n "$id" ]; then
      xdotool windowfocus "$id" || true
      sleep 1
      [ -n "$2" ] && xdotool type --delay 50 "$2"
      xdotool key Return
      echo "answered $1"
      return 0
    fi
    sleep 1
  done
  echo "no dialog: $1"
  return 1
}
answer "New key association request" "probe$(date +%s)"
answer "Browser Access Request" ""
