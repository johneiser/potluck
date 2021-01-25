import os, sys, argparse, logging, frida
from .interfaces import interfaces
from .interfaces import *
from .utils import log

LOG_FORMAT = "%(message)s"
LOG_FORMAT_FILE = "%(message)s"

AGENT = "agent.js"


def run(create=None, process=None, function=None, module=None, number=None, script=None, **kwargs):
    """
    Launch the debugger by injecting an agent into the target
    (or spawned) process, hook any specified functions, then
    present a command prompt with the appropriate interface.

    :param str create: spawn process with command
    :param str process: process (or pid) to attach to
    :param list functions: function names to hook
    :param list modules: modules to restrict hooks
    :param int number: number of function arguments in hooks
    :param file script: file containing scripted commands
    """
    
    # Read the agent to inject
    log.debug("Loading agent: %s", AGENT)
    with open(os.path.join(os.path.dirname(__file__), AGENT), "r") as f:
        source = f.read()

    # Create and configure command prompt interface
    prompt = base.Prompt(source)

    # Spawn a new process
    if create:
        prompt.cmdqueue.append("spawn %s" % create)

    # Attach to an existing process
    elif process:
        prompt.cmdqueue.append("attach %s" % process)

    # Hook specific functions
    if function:
        if module:
            if number:
                prompt.cmdqueue.append("hook %s %s %s" % (function, module, number))
            else:
                prompt.cmdqueue.append("hook %s %s" % (function, module))
        else:
            prompt.cmdqueue.append("hook %s" % function)

    # Automate commands for every hook
    if script:
        prompt.script = script.readlines()

    # Launch command prompt interface
    while True:
        with prompt:
            prompt.cmdloop()
    

def main():

    # Process arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--create", type=str, help="spawn a process")
    parser.add_argument("-p", "--process", type=str, help="attach to process")
    parser.add_argument("-f", "--function", type=str, help="hook function(s) by name")
    parser.add_argument("-m", "--module", type=str, help="restrict hooks to module(s)")
    parser.add_argument("-n", "--number", type=int, help="number of function arguments")
    parser.add_argument("-s", "--script", type=argparse.FileType("r"), help="file with commands to run for each hook")
    parser.add_argument("-v", "--verbose", action="store_true", help="print debug info")
    parser.add_argument("-l", "--log", type=str, help="log to file")
    args = parser.parse_args()
    kwargs = vars(args)

    # Configure stream logging
    formatter = logging.Formatter(LOG_FORMAT)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    handler.setFormatter(formatter)
    log.addHandler(handler)

    # Configure file logging
    if args.log:
        formatter = logging.Formatter(LOG_FORMAT_FILE)
        handler = logging.FileHandler(args.log)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        log.addHandler(handler)

    try:
        run(**kwargs)

    # Handle user cancellation
    except (KeyboardInterrupt, EOFError, base.Prompt.Interrupt):
        print("\r")

    # Handle known errors
    except (AssertionError, frida.InvalidOperationError) as e:
        log.error(e)

    # Handle unknown errors
    except Exception as e:
        log.exception(e)


if __name__ == "__main__":
    main()


