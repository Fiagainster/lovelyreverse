#!/bin/bash
# Drive the KeygenMe GTK window on Xvfb :99 entirely inside the virtual display.
# No Windows focus involvement: windowactivate/XTEST only touch the Xvfb server.
export DISPLAY=:99
W=$(xdotool search --name 'KeygenMe by int_0x80' | head -1)
[ -z "$W" ] && { echo "window not found"; exit 1; }
echo "driving window $W"
xdotool windowactivate --sync $W
sleep 0.5
xdotool getactivewindow && echo "(active ok)"
xdotool type --delay 60 'Root-Me'
sleep 0.3
xdotool key Tab
sleep 0.3
xdotool type --delay 60 '10844645039911251'
sleep 0.3
xdotool key Tab
sleep 0.3
xdotool key space
sleep 0.5
echo "input done"
