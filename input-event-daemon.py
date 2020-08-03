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

import pyudev
import evdev

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


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


async def monitor_events(device, bindings, command_queue):
    logger.info("monitoring device '{}'".format(device.path))
    while True:
        # Read key
        event = await device.async_read_one()
        event = evdev.categorize(event)

        if not isinstance(event, evdev.KeyEvent) or not event.keystate == evdev.KeyEvent.key_up:
            continue

        if isinstance(event.keycode, list):
            prefix = ([k for k in event.keycode if k != 'BTN_MOUSE'][0],)
        else:
            prefix = (event.keycode,)

        # Read extra keys if it might be the start of a combo
        try:
            while is_ambiguous(prefix, bindings.keys()):
                logger.debug("waiting for more inputs")
                event = await asyncio.wait_for(device.async_read_one(), timeout=1)
                event = evdev.categorize(event)
                if not isinstance(event, evdev.KeyEvent) or not event.keystate == evdev.KeyEvent.key_up:
                    continue
                if isinstance(event.keycode, list):
                    prefix += ([k for k in event.keycode if k != 'BTN_MOUSE'][0],)
                else:
                    prefix += (event.keycode,)
        except asyncio.TimeoutError:
            pass

        # Process command
        if prefix in bindings:  # otherwise discard garbage input
            logger.debug("handling {} on {}".format('+'.join(prefix), device.path))
            for cmd in bindings[prefix]:
                command_queue.put_nowait(cmd)


async def monitor_devices(monitor, bindings, command_queue, tasks):
    evt_queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    async def cb(device):
        await evt_queue.put(device)

    def cb2(device):
        asyncio.run_coroutine_threadsafe(cb(device), loop)

    observer = pyudev.MonitorObserver(
        monitor,
        callback=cb2,
        daemon=False)

    observer.start()

    while True:
        device = await evt_queue.get()
        if device.action == "add":
            for path in [device.device_node] + list(device.device_links):
                if path in bindings:
                    evdevice = evdev.InputDevice(device.device_node)
                    task = asyncio.create_task(monitor_events(
                        evdevice, bindings, command_queue))
                    tasks[device.device_number] = task, path
                    logger.info("device '{}' connected".format(path))
        elif device.action == "remove" and device.device_number in tasks:
            task, path = tasks.pop(device.device_number)
            task.cancel()
            logger.info("device '{}' disconnected".format(path))


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "--config", "-c",
        default="/etc/input-event-daemon.conf",
        help="configuration file")
    args = argparser.parse_args()

    # Parse configuration -----------------------------------------------------

    config = configparser.RawConfigParser()
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

    # Start command runner ----------------------------------------------------

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

    # Setup hooks -------------------------------------------------------------

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
            device_number = pyudev.Devices.from_device_file(context, path).device_number
            evdevice = evdev.InputDevice(path)
            task = loop.create_task(monitor_events(
                evdevice, bindings[path], command_queue))
            tasks[device_number] = task, path

    # setup connection/disconnection hook
    dev_mon_task = loop.create_task(
        monitor_devices(monitor, bindings, command_queue, tasks))

    # Run event loop ----------------------------------------------------------

    duh = loop.run_until_complete(dev_mon_task)
    raise duh.exception()


if __name__ == "__main__":
    main()
