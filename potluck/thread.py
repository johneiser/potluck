import logging, time, pprint, shlex 
from .prompt import Prompt, Message, Task, to_hex, tprint

log = logging.getLogger(__package__)



class ThreadInterface(Prompt):
    """
    Define the interface to be made available when
    interacting with a thread through the injected
    agent during a hook interrupt.
    """
    
    def call_from_thread(self, func, *args):
        """
        Call an exported function from a hooked thread.

        :param str func: function to call
        :param *args: arguments to provide the function
        """
        self.agent.post({
            "type": self.hook["thread"],
            "payload": [{
                "type": Task.CALL,
                "name": func,
                "args": args,
                }]
            })

    def do_exit(self, line):
        """exit
        resume execution, detach and quit"""
        self.do_continue(line)
        return True

    def do_continue(self, line):
        """continue
        resume the thread execution"""
        self.agent.post({
            "type": self.hook["thread"],
            "payload": [{"type": Task.RESUME }]})
        self.event.clear()

    def do_args(self, line):
        """args
        get arguments passed to the function"""
        pprint.pprint(self.hook.get("args"))

    def do_ret(self, line):
        """ret
        get the return value from the function"""
        pprint.pprint(self.hook.get("retval"))

    # TODO: get current thread / context
    # TODO: do_threads
    # TODO: do_modules
    # TODO: do_exports
    # TODO: do_functions
    # TODO: do_arch
    # TODO: do_platform
    # TODO: do_pid
    # TODO: do_tid

    def do_read(self, line):
        """read <addr> [size]
        read bytes from the specified address in the process"""
        args = shlex.split(line)

        # Parse address to read from
        addr = args[0]

        # Parse size to read
        try:
            size = int(args[1])
        except ValueError:
            size = int(args[1], 16)
        except IndexError:
            size = 32

        # Read from specified address
        self.call_from_thread("dump", addr, size)

        # Give time for frida to print
        time.sleep(0.1)

    def do_dump(self, line):
        """dump [arg] [size]
        dump bytes from the specified function argument"""
        args = shlex.split(line)

        # Parse size to read
        try:
            size = int(args[1])
        except ValueError:
            size = int(args[1], 16)
        except IndexError:
            size = 32

        # Read the specified argument
        try:
            addr = self.hook["args"][int(args[0])]
            self.call_from_thread("dump", addr, size)

        # Try to read from all arguments
        except IndexError:
            for a in self.hook["args"]:
                self.call_from_thread("dump", a, size)

        except ValueError:
            print("usage: dump [arg] [size]")
            return

        # Give time for frida to print
        time.sleep(0.1)

    def do_search(self, line):
        """search <pattern> <address> [size]
        search for a byte pattern after the specified address"""
        args = shlex.split(line)

        # Parse pattern
        try:
            pattern = args[0].encode().decode("unicode_escape")

        except IndexError:
            print("usage: search <pattern> [address] [size]")
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
            self.call_from_thread("searchAndDump", args[1], size, to_hex(pattern))

        # Search address from symbol name
        except ValueError:
            symbol = self.agent.exports.get_symbol_by_name(args[1])
            if symbol:
                self.call_from_thread("searchAndDump", args[1], size, to_hex(pattern))

        # Try to search all arguments for the pattern
        except IndexError:
            for a in self.hook["args"]:
                self.call_from_thread("searchAndDump", a, size, to_hex(pattern))

        time.sleep(0.1)
