import shlex, json, fnmatch, pprint, frida
from . import Interface
from ..utils import tformat, tprint, to_hex, parse_as, parse_line_as, int16


class AgentInterfaceBackbone(Interface):
    """
    Abstract interface with details for interacting with an injected agent
    """
    device      = None  # Device controlling the target process
    session     = None  # Session with the attached process
    agent       = None  # Agent injected into the attached process
    _image      = None  # Base image file path
    
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
            if isinstance(name, int):
                modules = self.agent.exports.get_module_by_address(name)

            # Fetch module by exact name
            else:
                modules = self.agent.exports.get_module_by_name(name)

                # Fetch module by similar name
                if not modules:
                    modules = [m for m in self.agent.exports.get_modules() if fnmatch.fnmatch(m["name"].lower(), name.lower())]
        
        # Fetch all modules
        else:
            modules = self.agent.exports.get_modules()

        return modules

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
            if isinstance(module, int):
                exports = self.agent.exports.get_exports_by_module_address(module)

            # Fetch exports by module name
            else:
                exports = self.agent.exports.get_exports_by_module_name(module)

                # Fetch exports by similar module name
                if not exports:
                    exports = []
                    for m in self.agent.exports.get_modules():
                        if fnmatch.fnmatch(m["name"].lower(), module.lower()):
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
            if isinstance(module, int):
                imports = self.agent.exports.get_imports_by_module_address(module)

            # Fetch imports by module name
            else:
                imports = self.agent.exports.get_imports_by_module_name(module)

                # Fetch imports by similar module name
                if not imports:
                    imports = []
                    for m in self.agent.exports.get_modules():
                        if fnmatch.fnmatch(m["name"].lower(), module.lower()):
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

    def get_functions(self, name=None, module=None):
        """
        Get a list of functions for an arbitrary name.

        :param str name: name or address to identify function(s)
        :return: matching functions
        :rtype: list
        """
        functions = None
        if name:

            # Fetch function by address
            if isinstance(name, int):
                function = self.agent.exports.get_symbol_by_address(name)
                if function:
                    functions = [function]

            # Fetch function by exact name
            else:
                functions = self.agent.exports.get_functions_named(name)

                # Fetch similar functions
                if not functions:
                    functions = self.agent.exports.get_functions_matching(name)

        # Fetch all functions
        else:
            functions = self.agent.exports.get_functions_matching("*")

        # Filter by module
        if module:
            for function in [f for f in functions]:
                m = self.agent.exports.get_module_by_address(function["address"])
                if m:

                    # Filter by module address
                    if isinstance(module, int):
                        if int16(m["base"]) != module:
                            self.log.info("removing, %s != %s", m["base"], module)
                            functions.remove(function)

                    # Filter by module name
                    else:
                        if not fnmatch.fnmatch(m["name"].lower(), module.lower()):
                            functions.remove(function)

        return functions

    def dump(self, address, size=32, limit=0):
        """
        Dump bytes from an arbitrary address.

        :param str address: address to read from
        :param int size: number of bytes to read
        :param int limit: recursion limit
        """

        # Dump from address
        if isinstance(address, int):
            self.agent.exports.dump(address, size, limit)

        # Dump from symbol name
        else:
            symbol = self.agent.exports.get_symbol_by_name(address)
            if symbol and symbol["address"]:
                self.log.info(symbol["name"])
                self.agent.exports.dump(symbol["address"], size, limit)
                return

            # Dump from export name
            exports = self.get_exports()
            if exports:
                for export in exports:
                    if fnmatch.fnmatch(export["name"].lower(), address.lower()):
                        self.log.info(export["name"])
                        self.agent.exports.dump(export["address"], size, limit)

    def search(self, pattern, address, size=1024, limit=0):
        """
        Search for a byte pattern at an arbitrary address.

        :param str pattern: pattern to search for
        :param str address: address to search at
        :param int size: range of bytes to search
        :param int limit: recursion limit
        """
        if pattern:

            # Search at address
            if isinstance(address, int):
                self.agent.exports.search_and_dump(to_hex(pattern), address, size, limit)

            # Search at symbol name
            else:
                symbol = self.agent.exports.get_symbol_by_name(address)
                if symbol and symbol["address"]:
                    self.log.info(symbol["name"])
                    self.agent.exports.search_and_dump(to_hex(pattern), symbol["address"], size, limit)
                    return

                # Search at export name
                exports = self.get_exports()
                if exports:
                    for export in exports:
                        if fnmatch.fnmatch(export["name"].lower(), address):
                            self.log.info(export["name"])
                            self.agent.exports.search_and_dump(to_hex(pattern), export["address"], size, limit)


class AgentInterface(AgentInterfaceBackbone):
    """
    Abstract interface with common commands for tasking an injected agent
    """
    device      = None  # Device controlling the target process
    session     = None  # Session with the attached process
    agent       = None  # Agent injected into the attached process
    _image      = None  # Base image file path
    
    @property
    def image(self):
        """Lazy image only captured when needed"""
        if not hasattr(self, "_image") or not self._image:
            if self.device.type != "local":
                raise FileNotFoundError("Remote frida-server in use, image base path not valid: %s" % self.agent.exports.get_image())
            self._image = self.agent.exports.get_image()
        return self._image

    @image.setter
    def image(self, value):
        """Enable override of default image"""
        self._image = value

        # Discard state
        self._state = None

    def do_image(self, line):
        """image
        get or set the base image file path"""

        (image,) = parse_line_as(line, [str])

        # Override default with custom image file path
        if image:
            self.image = image

        # Print current image file path
        print(self.image)

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

        # Parse arguments
        (protection,) = parse_line_as(line, [str, "---"])

        # Fetch mappings with given protection
        maps = self.agent.exports.get_ranges(protection)

        # Replace file object with its path component
        for m in maps:
            for k,v in m.items():
                if k == "file" and v is not None:
                    m[k] = v["path"]

        tprint(maps, sortby="base", align="l",
            field_names=["base", "size", "protection", "file"])

    def do_mallocs(self, line):
        """mallocs [protection]
        list of memory malloc ranges present in the process"""

        # Parse arguments
        (protection,) = parse_line_as(line, [str])

        # Fetch mallocs with given protection
        mallocs = self.agent.exports.get_malloc_ranges(protection)

        # Print mallocs
        tprint(mallocs, sortby="base", align="l")

    def do_modules(self, line):
        """modules [name]
        list the modules loaded in the process"""

        # Parse arguments
        (name,) = parse_line_as(line, [int16, str])

        # Fetch modules
        modules = self.get_modules(name)

        # Print modules
        tprint(modules, sortby="base", align="l",
            field_names=["name", "base", "size", "path"])

    def do_exports(self, line):
        """exports [module] [name]
        list exports for a given module"""

        # Parse arguments
        (module, name) = parse_line_as(line, [int16, str], [str])

        # Fetch exports
        exports = self.get_exports(module)

        # Filter by function name
        if exports and name:
            exports = [e for e in exports if fnmatch.fnmatch(e["name"].lower(), name.lower())]

        # Print exports
        tprint(exports, sortby="address", align="l",
            field_names=["address", "name", "type", "moduleName"])

    def do_imports(self, line):
        """imports [module] [name]
        list imports for a given module"""
        
        # Parse arguments
        (module, name) = parse_line_as(line, [int16, str], [str])

        # Fetch imports
        imports = self.get_imports(module)

        # Filter by function name
        if imports and name:
            imports = [i for i in imports if fnmatch.fnmatch(i["name"].lower(), name.lower())]

        # Print imports
        tprint(imports, sortby="address", align="l",
            field_names=["address", "name", "type", "moduleName"])

    def do_functions(self, line):
        """functions [name] [module]
        list functions present in the process"""

        # Parse arguments
        (name,module) = parse_line_as(line, [int16, str], [int16, str])

        # Fetch functions
        functions = self.get_functions(name, module)

        # Print functions
        tprint(functions, sortby="address", align="l",
            field_names=["address", "name", "moduleName"]) 
        
    def do_variables(self, line):
        """variables [name] [module]
        list variables exported by a given module"""
        
        # Parse arguments
        (name, module) = parse_line_as(line, [int16, str], [int16, str])

        # Fetch exports
        exports = self.get_exports(module)

        # Limit by variable type
        if exports:
            exports = [e for e in self.get_exports(module) if e["type"] == "variable"]
        
            # Filter by variable name
            if name:
                exports = [e for e in exports if fnmatch.fnmatch(e["name"].lower(), name.lower())]

        # Print variables
        tprint(exports, sortby="address", align="l",
            field_names=["address", "name", "moduleName"])

    def do_read(self, line):
        """read <address> [size] [limit]
        read bytes from the specified address"""

        # Parse arguments
        (address, size, limit) = parse_line_as(line, [int16, str], [int, int16, 32], [int, 0])

        # Validate required arguments
        if not address:
            print("Usage: read <address> [size] [limit]")
            return
        
        # Dump memory
        self.dump(address, size, limit)

    def do_search(self, line):
        """search <pattern> <address> [size] [limit]
        search for a byte pattern after the specified address"""

        # Parse arguments
        (pattern, address, size, limit) = parse_line_as(line, [str], [int16, str], [int, int16, 1024], [int, 0])
        
        # Validate required arguments
        if not pattern and address:
            print("Usage: search <pattern> <address> [size] [limit]")
            return

        # Search memory
        self.search(pattern, address, size, limit)
