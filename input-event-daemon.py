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

import evdev

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def drop_privileges(uid_name='nobody', gid_name='nobody'):
    # from https://stackoverflow.com/a/2699996/5786475
    if os.getuid() != 0:
        # We're not root so, like, whatever dude
        return

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Ensure a very conservative umask
    old_umask = os.umask(77)


def run_commands(command_queue, user="nobody", group="nobody", timeout=1):
    drop_privileges(user, group)
    while True:
        cmd = command_queue.get()
        if cmd is None:
            return

        subprocess.run(cmd, timeout=timeout, shell=True, check=False)


def is_ambiguous(keys, combinations):
    return any(combo[:len(keys)] == keys and len(combo) > len(keys)
               for combo in combinations)


async def event_handler(device, bindings, command_queue):
    while True:
        # Read key
        event = await device.async_read_one()
        event = evdev.categorize(event)
        if not isinstance(event, evdev.KeyEvent) or not event.keystate == evdev.KeyEvent.key_up:
            continue
        prefix = (event.keycode,)

        # Read extra keys if there it might be the start of a combo
        try:
            while is_ambiguous(prefix, bindings.keys()):
                event = await asyncio.wait_for(device.async_read_one(), timeout=1)
                event = evdev.categorize(event)
                if not isinstance(event, evdev.KeyEvent) or not event.keystate == evdev.KeyEvent.key_up:
                    continue
                prefix += (event.keycode,)
        except asyncio.TimeoutError:
            pass

        # Process command
        if prefix in bindings:  # erroneous input, discard
            logger.debug(f"handling {'+'.join(prefix)} on {device.path}")
            for cmd in bindings[prefix]:
                command_queue.put_nowait(cmd)


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--list", action='store_true',
                           help="list available devices and quit")
    argparser.add_argument("--config", "-c", default="/etc/input-event-daemon.conf",
                           help="configuration file")
    args = argparser.parse_args()

    # Parse configuration
    config = configparser.RawConfigParser()
    config.read(args.config)

    # Start command runner
    command_queue = multiprocessing.Queue(maxsize=100)
    user = config.get('commands', 'user', fallback="nobody")
    group = config.get('commands', 'user', fallback="nobody")
    timeout = config.getfloat('commands', 'timeout', fallback=1)
    command_worker = multiprocessing.Process(
        target=run_commands, args=[command_queue])

    def cleanup(*kargs):
        command_queue.put_nowait(None)
        command_worker.join()
        command_queue.close()
        logger.info("Exiting")
        sys.exit(0)

    # prevent children from capturing sigint
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    command_worker.start()
    # make sure to cleanly terminate when killed
    signal.signal(signal.SIGINT, cleanup)

    # Start input event handlers
    for device_name in (s for s in config.sections() if s != "commands"):
        # store commands
        bindings = {}
        for key in config[device_name].keys():
            commands = config[device_name].get(key)
            commands = [cmd.strip() for cmd in commands.splitlines()
                        if cmd.strip() != ""]
            key = tuple(k.upper().strip() for k in key.split("+"))
            bindings[key] = commands

        # set-up handler loop
        try:
            device = evdev.InputDevice(device_name)
        except IOError as e:
            logger.error(f"Failed to open {device_name}: {str(e)}")
            sys.exit(1)
        else:
            logger.info(f"Opened device {device_name}")
        asyncio.ensure_future(event_handler(device, bindings, command_queue))

    loop = asyncio.get_event_loop()
    loop.run_forever()


if __name__ == "__main__":
    main()
