import os, sys, argparse, logging, fnmatch, frida
from .prompt import Prompt
from .process import ProcessInterface
from .thread import ThreadInterface

log = logging.getLogger(__package__)
log.setLevel(logging.DEBUG)

AGENT = "agent.js"


def _fetch_modules(agent, modules):
    """
    Retrieve and normalize available modules.

    :param object agent: injected agent
    :param list modules: module names to filter
    :return: filtered module objects
    :rtype: list(dict)
    """
    if not isinstance(modules, list):
        modules = [modules]
    a = agent.exports.get_modules()
    for m in modules:
        for n in a:
            if fnmatch.fnmatch(n["name"], m):
                log.debug("Found module by name: %s", n)
                yield n


def _fetch_functions(agent, functions):
    """
    Retrieve and normalize available functions.

    :param object agent: injected agent
    :param list functions: function names to filter
    :return: filtered function objects
    :rtype: list(dict)
    """
    if not isinstance(functions, list):
        functions = [functions]
    for f in functions:
        for g in agent.exports.get_functions_matching(f):
            log.debug("Found function by name: %s", g)
            yield g


def run(spawn=None, process=None, functions=None, addresses=None, modules=None, number=3, run=None, **kwargs):
    """
    Launch the debugger by injecting an agent
    into the target (or spawned) process, hook
    any specified functions, then present a
    command prompt with the appropriate interface.

    :param str spawn: process to spawn
    :param str process: process to attach to
    :param list functions: function names to hook
    :param list addresses: function addresses to hook
    :param list modules: modules to restrict hooks
    :param int number: number of function arguments in hook
    :param bool verbose: print debug info
    :param str log: log to file
    """
    # Read the agent to inject
    log.debug("Loading agent: %s", AGENT)
    with open(os.path.join(os.path.dirname(__file__), AGENT), "r") as f:
        source = f.read()

    # Spawn process, if necessary
    if spawn:
        log.debug("Spawning process: %s", process)
        process = frida.spawn(spawn.split())

    # Check if process is a pid
    try:
        process = int(process)
    except ValueError:
        pass

    session = None
    prompt = None
    try:
        # Attach and inject agent
        log.debug("Attaching to process: %s", process)
        session = frida.attach(process)
        agent = session.create_script(source)

        # Register prompt callback
        log.debug("Registering prompt callback")
        Prompt.script = run.readlines() if run else []
        prompt = Prompt(session, agent)
        prompt.cmdqueue = [i for i in Prompt.script]
        agent.on("message", prompt.callback)
        agent.load()

        # Normalize hook requests
        if modules is not None:
            modules = list(_fetch_modules(agent, modules))
            log.debug("Found and restricting to %i modules", len(modules))
        functions = list(_fetch_functions(agent, functions)) if functions else []
        log.debug("Identified %i functions by name", len(functions))
        addresses = addresses or []
        log.debug("Identified %i addresses by name", len(addresses))

        hooked = False

        # Hook functions by name
        for function in functions:
            if modules is not None:
                module = agent.exports.get_module_by_address(function["address"])
                if not module or module["base"] not in [m["base"] for m in modules]:
                    log.debug("Ignoring: %s", function)
                    continue
            hooked = True
            agent.exports.hook(function["address"], number)

        # Hook addresses directly
        for address in addresses:
            if modules is not None:
                module = agent.exports.get_module_by_address(address)
                if not module or module["base"] not in [m["base"] for m in modules]:
                    log.debug("Ignoring: %s", address)
                    continue
            hooked = True
            agent.exports.hook(address, number)

        # Wait for hook, then interact with thread
        if hooked:
            log.debug("Proceeding hooked, applying thread interface")
            prompt.__class__ = ThreadInterface
            
        # Interact with process without hooks
        else:
            log.debug("Proceeding unhooked, applying process interface")
            prompt.__class__ = ProcessInterface
            prompt.event.set()

        # Resume process, if necessary
        if spawn:
            log.debug("Resuming process")
            frida.resume(process)

        # Open command prompt
        log.debug("Opening command prompt")
        prompt.cmdloop()

    except (frida.core.RPCException,) as e:
        log.error(e)
    
    finally:
        if session:
            log.debug("Detaching session: %s", session)
            session.detach()
        if spawn:
            log.debug("Killing process: %s", process)
            frida.kill(process)


def main():

    # Process arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--spawn", type=str, help="spawn a process")
    parser.add_argument("-p", "--process", type=str, help="attach to process")
    parser.add_argument("-f", "--function", dest="functions", type=str, action="append", help="hook function(s) by name")
    parser.add_argument("-a", "--address", dest="addresses", type=str, action="append", help="hook function(s) by address")
    parser.add_argument("-m", "--module", dest="modules", type=str, action="append", help="restrict hooks to module(s)")
    parser.add_argument("-n", "--number", type=int, help="number of function arguments", default=3) # TODO: find a better way to do this
    parser.add_argument("-r", "--run", type=argparse.FileType("r"), help="specify commands to run")
    parser.add_argument("-v", "--verbose", action="store_true", help="print debug info")
    parser.add_argument("-l", "--log", type=str, help="log to file")
    args = parser.parse_args()
    kwargs = vars(args)

    # Configure stream logging
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    log.addHandler(handler)

    # Configure file logging
    if args.log:
        handler = logging.FileHandler(args.log)
        handler.setLevel(logging.DEBUG)
        log.addHandler(handler)

    try:
        run(**kwargs)

    # Handle user cancellation
    except (KeyboardInterrupt, EOFError):
        print("\r")

    # Handle known errors
    except (AssertionError, frida.ProcessNotFoundError) as e:
        log.error(e)

    # Handle unknown errors
    except Exception as e:
        log.exception(e)


if __name__ == "__main__":
    main()


