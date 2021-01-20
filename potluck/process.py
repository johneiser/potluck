import logging, pprint, shlex, fnmatch, time
from .prompt import Prompt, Message, Task, to_hex, tprint
from .thread import ThreadInterface

log = logging.getLogger(__package__)


class ProcessInterface(Prompt):
    """
    Define the interface to be made available when
    interacting with a process through the injected
    agent.
    """
    
    def do_exit(self, line):
        """exit
        detach and quit"""
        return True

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

    def do_modules(self, line):
        """modules [name]
        list the modules loaded in the process"""
        mods = None
        if line:

            # Fetch module by address
            try:
                test = int(line, 16)
                mods = self.agent.exports.get_module_by_address(line)

            # Fetch module by exact name
            except ValueError:
                mods = self.agent.exports.get_module_by_name(line)

        # Fetch all modules
        else:
            mods = self.agent.exports.get_modules()
        
        # Fetch similar modules
        if not mods:
            mods = [m for m in self.agent.exports.get_modules() if fnmatch.fnmatch(m["name"], line)]

        tprint(mods, sortby="base", align="l")

    def do_functions(self, line):
        """functions [name]
        list the functions present in the process"""
        funcs = None
        if line:

            # Fetch function by address
            try:
                test = int(line, 16)
                funcs = self.agent.exports.get_symbol_by_address(line)

            # Fetch functions by exact name
            except ValueError:
                funcs = self.agent.exports.get_functions_named(line)

        # Fetch all functions
        else:
            funcs = self.agent.exports.get_functions_matching("*")
        
        # Fetch similar functions
        if not funcs:
            funcs = self.agent.exports.get_functions_matching(line)

        tprint(funcs, sortby="address", align="l")

    # TODO: do_maps
    # TODO: do_exports

    def do_hook(self, line):    # TODO: specify number of arguments...?
        """hook <function> [module]
        hook the specified function(s)"""
        args = shlex.split(line)

        # Fetch function by address
        try:
            test = int(args[0], 16)
            funcs = [{"address": args[0]}]

        # Fetch function by exact name
        except ValueError:
            funcs = self.agent.exports.get_functions_named(*args)

        except IndexError:
            print("usage: hook <function> [module]")
            return

        # Fetch similar functions
        if not funcs:
            funcs = self.agent.exports.get_functions_matching(*args)

        # Hook specified functions
        if funcs:
            for func in funcs:
                self.agent.exports.hook(func["address"])
            
            # Transition to thread interface
            self.__class__ = ThreadInterface
            self.event.clear()

    def do_read(self, line):
        """read <address> <size>
        read bytes from the specified address"""
        args = shlex.split(line)

        # Parse size to read
        try:
            size = int(args[1])
        except ValueError:
            size = int(args[1], 16)
        except IndexError:
            size = 32

        # Read from address
        try:
            test = int(args[0], 16)
            self.agent.exports.dump(args[0], size)

        # Read from symbol name
        except ValueError:
            symbol = self.agent.exports.get_symbol_by_name(args[0])
            if symbol:
                self.agent.exports.dump(symbol["address"], size)

        except IndexError:
            print("usage: read <address> <size>")
            return

        time.sleep(0.1)

    def do_search(self, line):
        """search <pattern> <address> [size]
        search for a byte pattern after the specified address"""
        args = shlex.split(line)

        # Parse pattern to search
        try:
            pattern = args[0].encode().decode("unicode_escape")
        except IndexError:
            print("usage: search <pattern> <address> [size]")
            return

        # Parse size to search
        try:
            size = int(args[2])
        except ValueError:
            size = int(args[2], 16)
        except IndexError:
            size = max(len(pattern), 32)

        # Parse address to read
        try:
            test = int(args[1], 16)
            self.agent.exports.search_and_dump(args[1], size,
                to_hex(args[0].encode().decode("unicode_escape")))

        # Read from symbol name
        except ValueError:
            symbol = self.agent.exports.get_symbol_by_name(args[1])
            if symbol:
                self.agent.exports.search_and_dump(symbol["address"], size,
                    to_hex(args[0].encode().decode("unicode_escape")))

        except IndexError:
            print("usage: search <pattern> <address> [size]")
            return

        time.sleep(0.1)
