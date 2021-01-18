import logging, time, pprint, shlex 
from .prompt import Prompt, Message, Task, to_hex

log = logging.getLogger(__package__)


class ThreadInterface(Prompt):
    """
    Define the interface to be made available when
    interacting the a thread through the injected
    agent during a hook interrupt.
    """
    
    def do_exit(self, line):
        """exit
        resume execution, detach and quit"""
        self.do_continue(line)
        return True

    def do_continue(self, line):
        """continue
        resume the thread execution"""
        self.agent.post(vars(Message(self.hook["thread"], [vars(Task(Task.RESUME))])))
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
        self.agent.post(vars(Message(self.hook["thread"], [
            vars(Task(Task.READ, {
                "addr" : addr,
                "size" : size,
            }))
        ])))

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
            self.agent.post(vars(Message(self.hook["thread"], [
                vars(Task(Task.READ, {
                    "addr" : addr,
                    "size" : size,
                }))
            ])))

        # Try to read from all arguments
        except IndexError:
            self.agent.post(vars(Message(self.hook["thread"], [
                vars(Task(Task.READ, {
                        "addr" : a,
                        "size" : size,
                    })) for a in self.hook["args"]
            ])))

        except ValueError:
            print("usage: dump [arg] [size]")

        # Give time for frida to print
        time.sleep(0.1)
