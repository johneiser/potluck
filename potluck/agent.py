import os
from fnmatch import fnmatch
from .utils import to_hex


# Read javascript agent source
with open(os.path.join(os.path.dirname(__file__), "agent.js"), "r") as f:
    source = f.read()


class Task:
    """
    Task codes available during a hooked thread interrupt.
    """
    NOP     = 0
    RESUME  = 1
    CALL    = 2


def get_modules(agent, name=None):
    """
    Get a list of loaded modules for an arbitrary name.

    :param object agent: injected frida agent
    :param str name: name or address to identify module(s)
    :return: matching modules
    :rtype: list
    """
    modules = None
    if name:

        # Fetch modules by address
        if isinstance(name, int):
            modules = agent.exports.get_module_by_address(name)

        # Fetch modules by name
        else:
            modules = [m for m in agent.exports.get_modules() if fnmatch(m["name"].lower(), name.lower())]

    # Fetch all modules
    else:
        modules = agent.exports.get_modules()

    return modules


def get_exports(agent, module=None, name=None):
    """
    Get a list of exports for a given module.

    :param object agent: injected frida agent
    :param str module: name or address to identify module(s)
    :param str name: name to identify export(s)
    :return: matching exports
    :rtype: list
    """
    exports = None
    modules = get_modules(agent, module)
    if modules:

        # Fetch exports from modules
        exports = []
        for m in modules:
            exports += agent.exports.get_exports_by_module_address(m["base"])

        # Filter exports by name
        if name:
            exports = [e for e in exports if fnmatch(e["name"].lower(), name.lower())]

    return exports


def get_imports(agent, module=None, name=None):
    """
    Get a list of imports for a given module.

    :param object agent: injected frida agent
    :param str module: name or address to identify module(s)
    :param str name: name to identify import(s)
    :return: matching imports
    :rtype: list
    """
    imports = None
    modules = get_modules(agent, module)
    if modules:

        # Fetch imports from modules
        imports = []
        for m in modules:
            imports += agent.exports.get_imports_by_module_address(m["base"])

        # Filter imports by name
        if name:
            imports = [i for i in imports if fnmatch(i["name"].lower(), name.lower())]

    return imports


def get_functions(agent, name=None, module=None):
    """
    Get a list of functions present in the process.

    :param object agent: injected frida agent
    :param str name: name or address to identify function(s)
    :param str module: name to identify module(s)
    :return: matching functions
    :rtype: list
    """
    functions = None
    if name:

        # Fetch function by address
        if isinstance(name, int):
            function = agent.exports.get_symbol_by_address(name)
            if function:
                functions = [function]

        # Fetch function by name
        else:
            functions = agent.exports.get_functions_matching(name)

    # Fetch all functions
    else:
        functions = agent.exports.get_functions_matching("*")

    # Filter by module
    if module:
        for function in [f for f in functions]:
            m = agent.exports.get_module_by_address(function["address"])
            if m:
                if not fnmatch(m["name"].lower(), module.lower()):
                    functions.remove(function)

    return functions


def dump(agent, address, size=32, limit=0):
    """
    Print out bytes from an arbitrary address.

    :param object agent: injected frida agent
    :param str address: address to read from
    :param int size: number of bytes to read
    :param int limit: recursion limit
    """

    # Dump from address
    if isinstance(address, int):
        agent.exports.dump(address, size, limit)

    # Dump from symbol name
    else:
        symbol = agent.exports.get_symbol_by_name(address)
        if symbol and symbol.get("address"):
            print("%s!%s" % (symbol["moduleName"], symbol["name"]))
            agent.exports.dump(symbol["address"], size, limit)
            return

        # Dump from export name
        exports = get_exports(agent)
        if exports:
            for export in exports:
                if fnmatch(export["name"].lower(), address.lower()):
                    print("%s!%s" % (export["moduleName"], export["name"]))
                    agent.exports.dump(export["address"], size, limit)


def search(agent, pattern, address=None, size=1024, limit=0):
    """
    Search for bytes from an arbitrary address.

    :param object agent: injected frida agent
    :param str pattern: byte pattern to search for
    :param int size: number of bytes to read
    :param int limit: recursion limit
    """
    if address:

        # Search at address
        if isinstance(address, int):
            agent.exports.search_and_dump(to_hex(pattern), address, size, limit)

        # Search at symbol name
        else:
            symbol = agent.exports.get_symbol_by_name(address)
            if symbol and symbol.get("address"):
                print("%s!%s" % (symbol["moduleName"], symbol["name"]))
                agent.exports.search_and_dump(to_hex(pattern), symbol["address"], size, limit)
                return

            # Search at export name
            exports = get_exports(agent)
            if exports:
                for export in exports:
                    if fnmatch(export["name"].lower(), address.lower()):
                        print("%s!%s" % (export["moduleName"], export["name"]))
                        agent.exports.search_and_dump(to_hex(pattern), symbol["address"], size, limit)

    # Search all addresses
    else:
        agent.exports.search_and_dump_all(to_hex(pattern))

