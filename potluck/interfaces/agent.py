import shlex, json, fnmatch, pprint, frida
from . import Interface
from ..utils import tformat, tprint, to_hex


class AgentInterface(Interface):
    """
    Abstract interface with common commands for tasking an injected agent
    """
    session     = None  # Session with the attached process
    agent       = None  # Agent injected into the attached process
    
    def do_pid(self, line):
        """pid
        get the process id"""
        print(self.agent.exports.get_pid())

    def do_arch(self, line):
        """arch
        get the target architecture"""
        print(self.agent.exports.get_arch())

    def do_platform(self, line):
        """platform
        get the target platform"""
        print(self.agent.exports.get_platform())

    def do_threads(self, line):
        """threads
        list the threads present in the process"""
        tprint(self.agent.exports.get_threads(), field_names=["id", "state"])

    def do_maps(self, line):
        """maps [protection]
        list the memory mappings present in the process"""

        # Parse optional argument
        try:
            (protection,) = shlex.split(line)
        except ValueError:
            protection = "---"

        # Fetch mappings with given protection
        maps = self.agent.exports.get_ranges(protection)

        # Replace file object with it's path component
        for m in maps:
            for k,v in m.items():
                if k == "file" and v is not None:
                    m[k] = v["path"]

        tprint(maps, sortby="base", align="l",
            field_names=["base", "size", "protection", "file"])

    def do_mallocs(self, line):
        """mallocs [protection]
        list of memory malloc ranges present in the process"""
        mallocs = self.agent.exports.get_malloc_ranges(line)
        tprint(mallocs, sortby="base", align="l")

    def get_modules(self, name=None):
        """
        Get a list of modules for an arbitrary name.

        :param str name: name or address to identify module(s)
        :return: matching modules
        :rtype: list
        """
        modules = None
        if name:

            # Fetch module by address
            try:
                test = int(name, 16)
                modules = self.agent.exports.get_module_by_address(name)

            # Fetch module by exact name
            except ValueError:
                modules = self.agent.exports.get_module_by_name(name)

                # Fetch similar modules
                if not modules:
                    modules = [m for m in self.agent.exports.get_modules() if fnmatch.fnmatch(m["name"], name)]

        # Fetch all modules
        else:
            modules = self.agent.exports.get_modules()

        return modules

    def do_modules(self, line):
        """modules [name]
        list the modules loaded in the process"""
        name = None

        # Parse arguments
        if line:
            try:
                (name,) = shlex.split(line)
            except ValueError as e:
                self.log.error(e)
                print("Usage: modules [name]")
                return

        tprint(self.get_modules(name), sortby="base", align="l",
            field_names=["name", "base", "size", "path"])

    def get_exports(self, module=None):
        """
        Get a list of exports for an arbitrary module name.

        :param str module: name or address to identify module(s)
        :return: matching exports
        :rtype: list
        """
        exports = None
        if module:

            # Fetch exports by module address
            try:
                test = int(module, 16)
                exports = self.agent.exports.get_exports_by_module_address(module)

            # Fetch exports by module name
            except ValueError:
                exports = self.agent.exports.get_exports_by_module_name(module)

                # Fetch exports by similar module name
                if not exports:
                    exports = []
                    for m in self.agent.exports.get_modules():
                        if fnmatch.fnmatch(m["name"], module):
                            e = self.agent.exports.get_exports_by_module_address(m["base"])
                            if e:
                                exports += e

        # Fetch all exports
        else:
            exports = []
            for m in self.agent.exports.get_modules():
                e = self.agent.exports.get_exports_by_module_address(m["base"])
                if e:
                    exports += e

        return exports

    def do_exports(self, line):
        """exports [module] [name]
        list exports for a given module"""
        module = None
        name = None

        # Parse optional arguments
        if line:
            try:
                (module, name) = shlex.split(line)
            except ValueError as e:

                # Parse required arguments
                try:
                    (module,) = shlex.split(line)
                except ValueError as e:
                    self.log.error(e)
                    print("Usage: exports <module> [name]")
                    return

        exports = self.get_exports(module)

        # Filter by function name
        if exports and name:
            exports = [e for e in exports if fnmatch.fnmatch(e["name"], name)]

        tprint(exports, field_names=["address", "name", "type"], sortby="address", align="l")

    def get_imports(self, module=None):
        """
        Get a list of imports for an arbitrary module name.

        :param str module: name or address to identify module(s)
        :return: matching imports
        :rtype: list
        """
        imports = None
        if module:

            # Fetch imports by module address
            try:
                test = int(module, 16)
                imports = self.agent.exports.get_imports_by_module_address(module)

            # Fetch imports by module name
            except ValueError:
                imports = self.agent.exports.get_imports_by_module_name(module)

                # Fetch imports by similar module name
                if not imports:
                    imports = []
                    for m in self.agent.exports.get_modules():
                        if fnmatch.fnmatch(m["name"], module):
                            i = self.agent.exports.get_imports_by_module_address(m["base"])
                            if i:
                                imports += i

        # Fetch all imports
        else:
            imports = []
            for m in self.agent.exports.get_modules():
                i = self.agent.exports.get_imports_by_module_address(m["base"])
                if i:
                    imports += i

        return imports

    def do_imports(self, line):
        """imports <module> [name]
        list imports for a given module"""
        module = None
        name = None

        # Parse optional arguments
        if line:
            try:
                (module, name) = shlex.split(line)
            except ValueError as e:
                name = None
                
                # Parse required arguments
                try:
                    (module,) = shlex.split(line)
                except ValueError as e:
                    self.log.error(e)
                    print("Usage: imports <module> [name]")
                    return

        imports = self.get_imports(module)

        # Filter by function name
        if imports and name:
            imports = [i for i in imports if fnmatch.fnmatch(i["name"], name)]

        tprint(imports, field_names=["address", "name", "type"], sortby="address", align="l")

    def get_functions(self, name=None):
        """
        Get a list of functions for an arbitrary name.

        :param str name: name or address to identify function(s)
        :return: matching functions
        :rtype: list
        """
        functions = None
        if name:

            # Fetch function by address
            try:
                test = int(name, 16)
                function = self.agent.exports.get_symbol_by_address(name)
                if function:
                    functions = [function]

            # Fetch function by exact name
            except ValueError:
                functions = self.agent.exports.get_functions_named(name)

                # Fetch similar functions
                if not functions:
                    functions = self.agent.exports.get_functions_matching(name)

        # Fetch all functions
        else:
            functions = self.agent.exports.get_functions_matching("*")

        return functions

    def do_functions(self, line):
        """functions [name]
        list functions present in the process"""
        name = None

        # Parse arguments
        if line:
            try:
                (name,) = shlex.split(line)
            except ValueError as e:
                self.log.error(e)
                print("Usage: functions [name]")
                return

        tprint(self.get_functions(name), sortby="address", align="l",
            field_names=["address", "name", "moduleName", "fileName", "lineNumber"])
        
    def do_variables(self, line):
        """variables [module] [name]
        list variables exported by a given module"""
        module = None
        name = None

        # Parse arguments
        if line:
            try:
                (module, name) = shlex.split(line)
            except ValueError as e:
                try:
                    (module,) = shlex.split(line)
                except ValueError as e:
                    self.log.error(e)
                    print("Usage: variables [module] [name]")
                    return

        exports = self.get_exports(module)

        # Limit by variable type
        if exports:
            exports = [e for e in self.get_exports(module) if e["type"] == "variable"]
        
            # Filter by variable name
            if name:
                exports = [e for e in exports if fnmatch.fnmatch(e["name"], name)]

        tprint(exports, sortby="address", align="l", field_names=["address", "name", "type"])

    def do_read(self, line):
        """read <address> [size]
        read bytes from the specified address"""
        
        # Parse optional arguments
        try:
            (address, size) = shlex.split(line)
        except ValueError as e:
            size = 32

            # Parse requried arguments
            try:
                (address,) = shlex.split(line)
            except ValueError as e:
                self.log.error(e)
                print("Usage: read <address> [size]")
                return

        # Parse size to read
        try:
            size = int(size)
        except ValueError:
            try:
                size = int(size, 16)
            except ValueError as e:
                self.log.error(e)
                print("Usage: read <address> [size]")
                return

        # Read from address
        try:
            test = int(address, 16)
            self.agent.exports.dump(address, size)

        # Read from symbol name
        except ValueError:
            symbol = self.agent.exports.get_symbol_by_name(address)
            if symbol and symbol["address"]:
                self.agent.exports.dump(symbol["address"], size)
                return

            # Read from export name
            exports = self.get_exports()
            if exports:
                for export in exports:
                    if fnmatch.fnmatch(export["name"], address):
                        print(export["address"])
                        self.agent.exports.dump(export["address"], size)

    def do_search(self, line):
        """search <pattern> <address> [size]
        search for a byte pattern after the specified address"""
        args = shlex.split(line)

        # Parse pattern to search
        try:
            pattern = args[0].encode().decode("unicode_escape")
        except IndexError:
            self.log.error(e)
            print("Usage: search <pattern> <address> [size]")
            return

        # Parse size to search
        try:
            size = int(args[2])
        except ValueError:
            try:
                size = int(args[2], 16)
            except ValueError as e:
                self.log.error(e)
                print("Usage: search <pattern> <address> [size]")
                return
        except IndexError:
            size = max(len(pattern), 32)

        # Search at address
        try:
            test = int(args[1], 16)
            self.agent.exports.search_and_dump(args[1], size, to_hex(pattern))

        # Search at symbol name
        except ValueError:
            symbol = self.agent.exports.get_symbol_by_name(args[1])
            if symbol and symbol["address"]:
                self.agent.exports.search_and_dump(symbol["address"], size, to_hex(pattern))
                return

            # Read from export name
            exports = self.get_exports()
            if exports:
                for export in exports:
                    if fnmatch.fnmatch(export["name"], address):
                        self.agent.exports.search_and_dump(exports["address"], size, to_hex(pattern))

        except IndexError as e:
            self.log.error(e)
            print("Usage: search <pattern> <address> [size]")
            return
