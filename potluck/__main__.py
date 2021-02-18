import os, sys, argparse, logging, frida
from .interfaces import Interface
from .interfaces import *
from .commands import *
from . import log, handler


def run(create=None, process=None, function=None, module=None, number=None, script=None, remote=None, **kwargs):
    """
    Launch the debugger by injecting an agent into the target
    (or spawned) process, hook any specified functions, then
    present a command prompt with the appropriate interface.

    :param str create: spawn process with command
    :param str process: process (or pid) to attach to
    :param list functions: function names to hook
    :param list modules: modules to restrict function hooks
    :param int number: number of function arguments in hooks
    :param file script: file containing scripted commands
    :param str remote: address of remote frida-server
    """
    # Create and configure command prompt interface
    interface = Interface()

    # Identify the device responsible for the process
    if remote:
        interface.device = frida.get_device_manager().add_remote_device(remote)
    else:
        interface.device = frida.get_local_device()

    # Spawn a new process
    if create:
        interface.cmdqueue.append("spawn %s" % create)

    # Attach to an existing process
    elif process:
        interface.cmdqueue.append("attach %s" % process)

    # Hook specific functions
    if function:
        if module:
            if number:
                interface.cmdqueue.append("hook %s %s %i" % (function, module, number))
            else:
                interface.cmdqueue.append("hook %s %s" % (function, module))
        else:
            if number:
                interface.cmdqueue.append("hook %s * %i" % (function, number))
            else:
                interface.cmdqueue.append("hook %s" % function)

    # Automate commands for every hook
    if script:
        interface.script = script.readlines()

        # Continue if scripted, but suspended
        if interface.script and function:
            interface.cmdqueue.append("continue")

    # Launch command prompt interface
    while True:
        with interface:
            interface.cmdloop()


def main():

    # Process arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--create", type=str, help="spawn a process")
    parser.add_argument("-p", "--process", type=str, help="attach to a process")
    parser.add_argument("-f", "--function", type=str, help="hook function(s) by name")
    parser.add_argument("-m", "--module", type=str, help="restrict hooks to module(s)")
    parser.add_argument("-n", "--number", type=int, help="number of function arguments")    # TODO: automatically detect?
    parser.add_argument("-s", "--script", type=argparse.FileType("r"), help="file with commands to run for each hook")
    parser.add_argument("-r", "--remote", type=str, help="address of remote frida-server")
    parser.add_argument("-v", "--verbose", action="store_true", help="print debug info")
    args = parser.parse_args()
    kwargs = vars(args)

    if args.verbose:
        handler.setLevel(logging.DEBUG)

    try:
        run(**kwargs)

    # Handle user cancellation
    except (KeyboardInterrupt, EOFError):
        sys.stdout.write("\r")

    # Handle known errors
    except (AssertionError,
            frida.InvalidOperationError,
            frida.ServerNotRunningError) as e:
        log.error(e)

    # Handle unknown errors
    except Exception as e:
        log.exception(e)
