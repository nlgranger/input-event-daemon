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

- python 3.5
- [python-evdev](https://github.com/gvalkov/python-evdev)

**Caution** depending of your distro, you might need to upgrade asyncio and evdev to latest release (it was my case on an OrangePi+2E running Ubuntu Xenial based Armbian distro, altrough Python 3 revision is 3.5.1)

Id did this by setting-up a python3 venv, then upgraded asyncio and evdev:

```shell
apt-get install python3-venv python3-wheel python3-setuptools libpython3-dev build-essential
python3 -m venv /opt/input-event-daemon
pip install --upgrade asyncio
pip install --upgrade evdev
```

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

## working with IR remote

You need **ir-keytable** installed on your system. on **Debian** based systems, ```apt-get install ir-keytable```

This package comes with many pre-configured key-mappings for many remotes control. They are listed into ```/lib/udev/rc_keymaps``` directory.

If your remote is not listed, *or* you wish to tweak it, you can still edit your own keymapping. To detect the scancodes emitted by your remote control, you can use ```ir-keytable``` in **test** mode:

```shell
# ir-keytable -s rc0 -t
Testing events. Please, press CTRL-C to abort.
1566464718.098615: event type EV_MSC(0x04): scancode = 0x877c0c
1566464718.098615: event type EV_KEY(0x01) key_down: KEY_1(0x0002)
1566464718.098615: event type EV_SYN(0x00).
1566464718.150853: event type EV_MSC(0x04): scancode = 0x877c0c
1566464718.150853: event type EV_SYN(0x00).
1566464718.259850: event type EV_MSC(0x04): scancode = 0x877c0c
1566464718.259850: event type EV_SYN(0x00).
1566464718.493633: event type EV_KEY(0x01) key_up: KEY_1(0x0002)
1566464718.493633: event type EV_SYN(0x00).
```

In the example above, the button **1** from my NAD remote control emmits the scancode *0x877c0c*, which is mapped to *KEY_1*

Configure **udev** rules ```/etc/udev/rules.d/60-ir-keytable.rules```:

```shell
ACTION=="add", ATTRS{name}=="sunxi-ir", RUN+="/usr/bin/ir-keytable -c -w /opt/input-event-daemon/udev/nec_nad --sysdev rc0"
```
