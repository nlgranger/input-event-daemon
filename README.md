# Input Event Daemon

A daemon that monitors key events from input devices and runs user-defined
commands accordingly. For convenience, a small timout is started after a key
press in order to wait for additional inputs to form a combination.

This daemon supports any device managed by the evdev kernel system, so
virtually any keyboard. A few ARM boards also feature an IR receiver. When a
kernel driver is available as it is the case with Cubieboards for example, one
can use the evdev device directly instead.

Note: this project is independent from the excellent but unmaintained daemon made by [gandro](https://github.com/gandro/input-event-daemon).


## Dependencies

- python 3
- [python-evdev](https://github.com/gvalkov/python-evdev)


## Configuration

```ini
[commands]
user = nobody  ; user to run commands as
group = nobody

[/dev/input/event0]
KEY_1 =
    mpc listall | head -12 | tail -1 | mpc add  ; pipes are supported
    mpc play  ; several commands can be given
# ...
KEY_1 + KEY_2 =  ; key combos are supported
    mpc listall | head -12 | tail -1 | mpc add
    mpc play
```