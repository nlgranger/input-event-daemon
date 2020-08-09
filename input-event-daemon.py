#!/usr/bin/env python3

import argparse
import asyncio
import configparser
import grp
import logging
import multiprocessing
import os
import pwd
import signal
import subprocess
import sys
import textwrap

import evdev
import evdev.ecodes
import pyudev

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# Utility ---------------------------------------------------------------------

def drop_privileges(uid_name='nobody', gid_name='nobody'):
    """Drop user an group for current process."""
    # from https://stackoverflow.com/a/2699996/5786475

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Ensure a very conservative umask
    os.umask(77)


def run_commands(command_queue, user="nobody", group="nobody", timeout=1):
    """Fetch commands from a queue and run them."""
    drop_privileges(user, group)
    while True:
        cmd = command_queue.get()
        if cmd is None:
            return

        subprocess.run(cmd, timeout=timeout, shell=True, check=False)


def is_ambiguous(keys, combinations):
    """Return wether an input partially matches a key combination."""
    return any(combo[:len(keys)] == keys and len(combo) > len(keys)
               for combo in combinations)


# Debug -----------------------------------------------------------------------

def print_devices():
    for path in evdev.list_devices():
        evdevice = evdev.InputDevice(path)
        cap = evdevice.capabilities()
        if evdev.ecodes.EV_KEY in cap:
            print("- path : {}".format(evdevice.path))
            print("  name : {}".format(evdevice.name))
            keys = [evdev.ecodes.keys[k] for k in cap[evdev.ecodes.EV_KEY]]
            keys = [k[0] if isinstance(k, list) else k for k in keys]
            keys = ", ".join(keys)
            keys = "\n".join(textwrap.wrap(keys, width=65))
            keys = textwrap.indent(keys, prefix="    ")
            print("  keys :")
            print(keys)
            print()


async def probe_events(device, queue):
    print("monitoring {}".format(device.path))

    try:
        async for event in device.async_read_loop():
            event = evdev.categorize(event)

            if not isinstance(event, evdev.KeyEvent) \
                    or not event.keystate == evdev.KeyEvent.key_up:
                continue

            if isinstance(event.keycode, list):
                keycode = [k for k in event.keycode if k != 'BTN_MOUSE'][0]
            else:
                keycode = event.keycode

            await queue.put((device.path, keycode))
    except asyncio.CancelledError:
        device.close()
        raise


async def log_events(queue):
    last_path = ""
    while True:
        path, keycode = await queue.get()
        print("{:30s} : {}".format(path if path != last_path else "", keycode))
        last_path = path


def probe_devices():
    loop = asyncio.new_event_loop()
    queue = asyncio.Queue(loop=loop)
    tasks = []

    for path in evdev.list_devices():
        device = evdev.InputDevice(path)
        t = loop.create_task(probe_events(device, queue))
        tasks.append(t)

    t = loop.create_task(log_events(queue))
    tasks.append(t)

    tasks = asyncio.gather(*tasks, loop=loop, return_exceptions=True)

    def cleanup(signum, frame):
        tasks.cancel()

    signal.signal(signal.SIGINT, cleanup)

    # prevent worker and children from capturing sigint
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.remove_signal_handler(sig)

    try:
        loop.run_until_complete(tasks)
    except asyncio.CancelledError:
        sys.exit(0)
    finally:
        loop.stop()
        loop.close()


# Event loops -----------------------------------------------------------------

async def monitor_events(device, bindings, command_queue):
    logger.info("monitoring device '{}'".format(device.path))
    while True:
        # Read key
        event = await device.async_read_one()
        event = evdev.categorize(event)

        if not isinstance(event, evdev.KeyEvent) \
                or not event.keystate == evdev.KeyEvent.key_up:
            continue

        if isinstance(event.keycode, list):
            prefix = ([k for k in event.keycode if k != 'BTN_MOUSE'][0],)
        else:
            prefix = (event.keycode,)

        # Read extra keys if it might be the start of a combo
        try:
            while is_ambiguous(prefix, bindings.keys()):
                logger.debug("waiting for more inputs")
                event = await asyncio.wait_for(
                    device.async_read_one(), timeout=1)
                event = evdev.categorize(event)
                if not isinstance(event, evdev.KeyEvent) \
                        or not event.keystate == evdev.KeyEvent.key_up:
                    continue
                if isinstance(event.keycode, list):
                    prefix += ([k for k in event.keycode
                                if k != 'BTN_MOUSE'][0],)
                else:
                    prefix += (event.keycode,)
        except asyncio.TimeoutError:
            pass

        # Process command
        if prefix in bindings:  # otherwise discard garbage input
            logger.debug("handling {} on {}".format(
                '+'.join(prefix), device.path))
            for cmd in bindings[prefix]:
                command_queue.put_nowait(cmd)


def match_udev_evt_bindings(udev_evt, bindings):
    if udev_evt.device_node in bindings:
        return udev_evt.device_node
    if any(path in bindings for path in udev_evt.device_links):
        for path in udev_evt.device_links:
            if path in bindings:
                return path
    elif evdev.InputDevice(udev_evt.device_node).name in bindings:
        return evdev.InputDevice(udev_evt.device_node).name
    else:
        return None


async def monitor_devices(monitor, bindings, command_queue, tasks):
    evt_queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def cb(d):
        asyncio.run_coroutine_threadsafe(evt_queue.put(d), loop)

    observer = pyudev.MonitorObserver(
        monitor,
        callback=cb,
        daemon=False)

    observer.start()

    while True:
        udev_evt = await evt_queue.get()
        if udev_evt.action == "add" and udev_evt.device_node is not None:
            if not evdev.util.is_device(udev_evt.device_node):
                continue
            try:
                device = evdev.InputDevice(udev_evt.device_node)
            except OSError:
                continue

            bindings_key = match_udev_evt_bindings(udev_evt, bindings)
            if bindings_key is None:
                continue

            task = asyncio.create_task(monitor_events(
                device, bindings[bindings_key], command_queue))

            tasks[udev_evt.device_number] = task, udev_evt.device_node

            logger.info("device '{}' connected".format(udev_evt.device_node))

        elif udev_evt.action == "remove" and udev_evt.device_number in tasks:
            task, path = tasks.pop(udev_evt.device_number)
            task.cancel()

            logger.info("device '{}' disconnected".format(path))


# -----------------------------------------------------------------------------

def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "--config", "-c",
        default="/etc/input-event-daemon.conf",
        help="configuration file")
    argparser.add_argument(
        "--probe",
        action="store_true",
        help="log key-presses from all devices for debugging purpose")
    argparser.add_argument(
        "--list",
        action="store_true",
        help="describe all available devices and exit")
    args = argparser.parse_args()

    # Handle special actions instead of running the daemon
    if args.list:
        print_devices()
        sys.exit(0)
    elif args.probe:
        probe_devices()

    # Parse configuration

    config = configparser.ConfigParser(inline_comment_prefixes=(';', '#'))
    config.read(args.config)

    logger.setLevel(config.get('general', 'loglevel', fallback='INFO').upper())

    if config.has_section('commands'):
        logging.warning("the [command] section is deprecated, "
                        "its items have moved into [general]")
        for key in ['user', 'group', 'timeout']:
            if config.has_option('command', key):
                config.set('general', config.get('command', key))

    bindings = {}
    for device_name in (s for s in config.sections() if s != "commands"):
        # store commands
        dev_bindings = {}
        for key in config[device_name].keys():
            commands = config[device_name].get(key)
            commands = [cmd.strip() for cmd in commands.splitlines()
                        if cmd.strip() != ""]
            key = tuple(k.upper().strip() for k in key.split("+"))
            dev_bindings[key] = commands

        bindings[device_name] = dev_bindings

    # Start command runner

    command_queue = multiprocessing.Queue(maxsize=100)
    user = config.get('general', 'user', fallback="nobody")
    group = config.get('general', 'group', fallback="nobody")
    timeout = config.getfloat('general', 'timeout', fallback=1)
    command_worker = multiprocessing.Process(
        target=run_commands, args=(command_queue, user, group, timeout))

    def cleanup(signum, frame):
        command_queue.put_nowait(None)
        command_worker.join()
        command_queue.close()
        logger.info("Exiting")
        sys.exit(0)

    # prevent worker and children from capturing sigint
    sig_hdl = signal.signal(signal.SIGINT, signal.SIG_IGN)
    command_worker.start()
    signal.signal(signal.SIGINT, sig_hdl)

    # make sure to cleanly terminate when killed
    signal.signal(signal.SIGINT, cleanup)

    # Setup hooks

    # monitor device plug/unplug
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by('input')

    # start monitring available devices
    tasks = {}
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    for path in evdev.list_devices():
        if path in bindings:
            bindings_key = path
        elif evdev.InputDevice(path).name in bindings:
            bindings_key = evdev.InputDevice(path).name
        else:
            continue

        device = evdev.InputDevice(path)
        device_number = pyudev.Devices.from_device_file(
            context, path).device_number
        task = loop.create_task(monitor_events(
            device, bindings[bindings_key], command_queue))
        tasks[device_number] = task, path

    # setup connection/disconnection hook
    loop.create_task(
        monitor_devices(monitor, bindings, command_queue, tasks))

    # Run event loop
    loop.run_forever()


if __name__ == "__main__":
    main()
