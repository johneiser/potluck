import shlex, json, queue
from . import Interface
from .agent import AgentInterface
from ..utils import tformat, tprint, to_hex


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
    def args(self):
        return self.hook.get("args")

    @property
    def ret(self):
        return self.hook.get("ret")

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

    def do_dump(self, line):
        """dump [arg] [size]
        dump bytes from the specified argument"""
        args = shlex.split(line)

        # Parse size to read 
        try:
            size = int(args[1])
        except ValueError:
            size = int(args[1], 16)
        except IndexError:
            size = 32

        # Read from the specified argument
        try:
            addr = self.args[int(args[0])]
            self.agent.exports.dump(addr, size)

        # Try to read from all arguments
        except IndexError:
            for addr in self.args:
                self.agent.exports.dump(addr, size)

    def do_dumpret(self, line):
        """dumpret [arg]
        dump bytes from the specified argument with the size of the return value"""
        args = shlex.split(line)

        # Read from the specified argument
        try:
            addr = self.args[int(args[0])]
            self.agent.exports.dump(addr, int(self.ret, 16))

        # Try to read from all arguments
        except IndexError:
            for addr in self.args:
                self.agent.exports.dump(addr, int(self.ret, 16))

    def do_find(self, line):
        """find <pattern> [arg] [size]
        search for pattern in the bytes pointed to by the specified argument"""
        args = shlex.split(line)

        # Parse pattern to search
        try:
            pattern = args[0].encode().decode("unicode_escape")
        except IndexError:
            self.log.error(e)
            print("Usage: find <pattern> [arg] [size]")
            return

        # Parse size to search
        try:
            size = int(args[2])
        except ValueError:
            try:
                size = int(args[2], 16)
            except ValueError:
                self.log.error(e)
                print("Usage: find <pattern> [arg] [size]")
                return
        except IndexError:
            size = max(len(pattern), 32)

        # Search the specified argument
        try:
            addr = self.args[int(args[1])]
            self.agent.exports.search_and_dump(addr, size, to_hex(pattern))

        # Search all arguments
        except IndexError:
            for addr in self.args:
                self.agent.exports.search_and_dump(addr, size, to_hex(pattern))

    def do_findret(self, line):
        """find <pattern> [arg]
        search for pattern in the bytes pointed to by the specified argument for a length of the return value"""
        args = shlex.split(line)

        # Parse pattern to search
        try:
            pattern = args[0].encode().decode("unicode_escape")
        except IndexError:
            self.log.error(e)
            print("Usage: findret <pattern> [arg]")
            return

        # Search the specified argument
        try:
            addr = self.args[int(args[1])]
            self.agent.exports.search_and_dump(addr,
                int(self.ret, 16), to_hex(pattern))

        # Search all arguments
        except IndexError:
            for addr in self.args:
                self.agent.exports.search_and_dump(addr,
                    int(self.ret, 16), to_hex(pattern))

