#!/bin/bash
export DISPLAY=:99
W=2097155
echo "== tree of main window =="
xwininfo -id $W -tree 2>/dev/null | sed 's/^ *//' | grep -v '^$'
echo
echo "== child window geometry (mapped children only) =="
for cid in $(xwininfo -id $W -children 2>/dev/null | grep -oE '0x[0-9a-f]+' | tail -n +2); do
  echo "-- child $cid"
  xwininfo -id $cid -stats 2>/dev/null | grep -E 'Absolute|Width|Height|Map State' | sed 's/^ *//'
done
