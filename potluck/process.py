import logging, pprint, shlex, fnmatch 
from .prompt import Prompt, Message, Task, to_hex

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
        pprint.pprint(self.agent.exports.get_threads())

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
       
        pprint.pprint(mods)

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
      
        pprint.pprint(funcs)

    # TODO: do_maps
