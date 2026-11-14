#!/bin/bash
# Deterministic final pass: refill both entries by coordinate clicks, then Validate.
export DISPLAY=:99
click() { xdotool mousemove "$1" "$2" sleep 0.25 click 1; sleep 0.3; }
fill()  { click "$1" "$2"; xdotool key --clearmodifiers ctrl+a; sleep 0.2; xdotool type --delay 45 "$3"; sleep 0.3; }
# layout (from screenshots): name entry ~y425, serial entry ~y455, validate ~y485
fill 510 425 'Root-Me'
fill 510 455 '10844645039911251'
click 510 485
echo "final-pass input done"
