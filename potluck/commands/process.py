from . import command
from ..utils import parse_line_as, int16, tprint
from ..agent import get_modules, get_exports, get_imports, get_functions


@command("ProcessInterface", "ThreadInterface")
def do_pid(self, line):
    """pid
    get the process id"""
    print(self.agent.exports.get_pid())


@command("ProcessInterface", "ThreadInterface")
def do_threads(self, line):
    """threads
    list the threads present in the process"""
    tprint(self.agent.exports.get_threads(), field_names=["id", "state"])


@command("ProcessInterface", "ThreadInterface")
def do_modules(self, line):
    """modules [name]
    list modules loaded in the process"""

    # Parse arguments
    (name,) = parse_line_as(line, [int16, str])

    # Fetch modules
    modules = get_modules(self.agent, name)

    # Print modules
    tprint(modules, sortby="base", align="l",
        field_names=["name", "base", "size", "path"])


@command("ProcessInterface", "ThreadInterface")
def do_exports(self, line):
    """exports [module] [name]
    list exports for a given module"""

    # Parse arguments
    (module, name) = parse_line_as(line, [int16, str], [str])

    # Fetch exports
    exports = get_exports(self.agent, module, name)

    # Print exports
    tprint(exports, sortby="address", align="l",
        field_names=["address", "name", "type", "moduleName"])


@command("ProcessInterface", "ThreadInterface")
def do_imports(self, line):
    """imports [module] [name]
    list imports for a given module"""

    # Parse arguments
    (module, name) = parse_line_as(line, [int16, str], [str])

    # Fetch imports
    imports = get_imports(self.agent, module, name)

    # Print imports
    tprint(imports, sortby="address", align="l",
        field_names=["address", "name", "type", "moduleName"])


@command("ProcessInterface", "ThreadInterface")
def do_functions(self, line):
    """functions [name] [module]
    list functions present in the process"""

    # Parse arguments
    (name, module) = parse_line_as(line, [int16, str], [str])

    # Fetch functions
    functions = get_functions(self.agent, name, module)

    # Print functions
    tprint(functions, sortby="address", align="l",
        field_names=["address", "name", "moduleName"])

