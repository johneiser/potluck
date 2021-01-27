import shlex, json, queue, logging
from . import Interface
from .agent import AgentInterface
from ..utils import tformat, tprint, to_hex, parse_as, parse_line_as, int16


class Task:
    """
    Define a task that the agent should perform
    during a hook interrupt.
    """
    NOP     = 0
    RESUME  = 1
    CALL    = 2


class ThreadInterface(AgentInterface):
    """
    Interface that supports being attached to a hooked thread.
    """
    session     = None  # Session with the attached process
    agent       = None  # Agent injected into the attached process
    script      = None  # Script to run for each hook
    hook        = None  # Context of current hook

    @classmethod
    def qualify(cls, self):
        """Evaluate the environment for this interface"""
        assert hasattr(self, "session") and self.session is not None
        assert hasattr(self, "agent") and self.agent is not None
        assert hasattr(self, "hook") and self.hook is not None and "thread" in self.hook
        return cls

    def _exit(self):
        """Called when exiting the prompt"""

        try:
            # Remove hooks
            self.log.debug("Removing hooks from session: %s", self.session)
            self.agent.exports.unhook()

            # Cycle through queue
            try:
                while self.hook:

                    # Resume hooked thread
                    self.log.debug("Resuming hooked thread: %s", self.thread)
                    self.agent.post({
                        "type" : self.thread,
                        "payload" : [
                            { "type" : Task.RESUME },
                        ]})

                    # Pull next hook
                    self.hook = self.queue.get(False)
                    
            except queue.Empty:
                pass

        # Disqualify interface
        finally:
            self.hook = None

    @property
    def prompt(self):
        return "[%s => %i]> " % (self.session, self.thread)

    @property
    def thread(self):
        return self.hook.get("thread")

    @property
    def func(self):
        return self.hook.get("func")

    @property
    def addr(self):
        return self.hook.get("addr")
    
    @property
    def args(self):
        return self.hook.get("args")

    @property
    def ret(self):
        return self.hook.get("ret")

    @property
    def context(self):
        return self.hook.get("context")

    def callback(self, message, data):
        """Called when a message is received from the agent"""
        try:
            # Check if message is blocking
            if message.get("thread", None):

                # Add hook to queue
                self.queue.put(message)

        except KeyError as e:
            self.log.warning("Failed to process message, missing key: %s", e)
        
    def do_unhook(self, line):
        """unhook
        remove all hooks and resume"""
        self._exit()

    def do_continue(self, line):
        """continue
        resume the thread execution"""

        # Resume thread
        self.log.debug("Resuming hooked thread: %s", self.thread)
        self.agent.post({
            "type" : self.thread,
            "payload" : [
                { "type" : Task.RESUME },
            ]})

        # Pull next hook
        try:
            self.hook = self.queue.get(False)
        
        # Switch to process interface
        except queue.Empty:
            self.hook = None
            self._adapt()

            # Hold prompt
            self.event.clear()

    def do_tid(self, line):
        """tid
        get the thread id of current hook"""
        print(self.thread)

    def do_args(self, line):
        """args
        list the function arguments of the current hook"""
        print(self.args)

    def do_ret(self, line):
        """ret
        get the return value of the current hook"""
        print(self.ret)

    # TODO: Better formalize hook state interface

    #def do_func(self, line):
    #    """func
    #    get the details of the current hook function"""
    #    tprint(self.func)

    # Overload read to enable argument specification
    def do_read(self, line):
        """read [address|arg] [size] [limit]
        read bytes from the specified address"""

        # Parse arguments
        (address, size, limit) = parse_line_as(line, [int, int16, str], [int, int16, 32], [int, 0])

        # Read from the specified argument
        if address is not None:
            if isinstance(address, int):
                try:
                    self.dump(int16(self.args[address]), size, limit)
                    return
                except IndexError:
                    pass

            # Read from the specified address
            self.dump(address, size, limit)

        # Read from all arguments, recursively
        else:
            for arg in self.args:
                self.dump(int16(arg), size, 5)

    # Overload search to enable argument specification
    def do_search(self, line):
        """search <pattern> [address|arg] [size] [limit]
        search for a byte pattern at the specified address"""

        # Parse arguments
        (pattern, address, size, limit) = parse_line_as(line, [str], [int, int16, str], [int, int16, 1024], [int, 0])

        # Validate required arguments
        if not pattern:
            print("Usage: search <pattern> [address|arg] [size] [limit]")
            return

        # Normalize pattern
        pattern = pattern.encode().decode("unicode_escape")

        # Search address of argument
        if address:
            if isinstance(address, int):
                try:
                    self.search(pattern, int16(self.args[address]), size, limit)
                
                # Search address directly
                except IndexError:
                    self.search(pattern, address, size, limit)

        # Search through all arguments, recursively
        else:
            for arg in self.args:
                self.search(pattern, int16(arg), size, 5)

