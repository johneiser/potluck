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
        """read [address|arg] [size]
        read bytes from the specified address"""

        # Parse arguments
        (address, size) = parse_line_as(line, [int, int16, str], [int, int16, 32])

        # Read from the specified argument
        if address:
            if isinstance(address, int):
                try:
                    self.dump(int16(self.args[address]), size)
                    return
                except IndexError:
                    pass

            # Read from the specified address
            self.dump(address, size)

        # Read from all arguments
        else:
            for arg in self.args:
                self.dump(int16(arg), size)

    # TODO: recursive read
    # TODO: recursive search

    # Overload search to enable argument specification
    def do_search(self, line):
        """search <pattern> [address|arg] [size]
        search for a byte pattern at the specified address"""

        # Parse arguments
        (pattern, address, size) = parse_line_as(line, [str], [int, int16, str], [int, int16, 1024])

        # Validate required arguments
        if not pattern:
            print("Usage: search <pattern> [address|arg] [size]")
            return

        # Normalize pattern
        pattern = pattern.encode().decode("unicode_escape")

        # Search address of argument
        if address:
            if isinstance(address, int):
                try:
                    self.search(pattern, int16(self.args[address]), size)
                
                # Search address directly
                except IndexError:
                    self.search(pattern, address, size)

        # Search through all arguments
        else:
            for arg in self.args:
                self.search(pattern, int16(arg), size)

    def do_simulate(self, line):
        """simulate <file>
        capture the state of the target for simulation"""

        # TODO: automatic on each hook

        try:
            # Import angr and remove added logging handler
            self.log.debug("Importing angr")
            import angr
            for handler in self.log.parent.handlers:
                if isinstance(handler, angr.misc.loggers.CuteHandler):
                    self.log.parent.removeHandler(handler)
                    self.log.debug("Removing log handler: %s", handler)

            # Create a concrete target
            self.log.debug("Creating concrete target...")
            from .angr_target import FridaConcreteTarget
            ct = FridaConcreteTarget(self.agent, self.context)
            self.log.debug("Created concrete target: %s", ct)

            # Create an angr project with a concrete target
            self.log.debug("Creating angr project from file: %s", line)
            p = angr.Project(line, concrete_target=ct, use_sim_procedures=True)
            self.log.debug("Created angr project: %s", p)
            
            # Create an entry state
            self.log.debug("Creating entry state...")
            entry_state = p.factory.entry_state()
            entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
            entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
            self.log.debug("Created entry state: %s", entry_state)

            # Create a simulation manager from the entry state
            self.log.debug("Creating simulation manager...")
            simgr = p.factory.simgr(entry_state)
            self.log.debug("Created simulation manager: %s", simgr)
            
            # Sync with the concrete target
            self.log.debug("Syncing state with concrete target...")
            simgr.use_technique(angr.exploration_techniques.Symbion(find=[int(self.addr,16)]))
            exploration = simgr.run()
            self.log.debug("Sync complete: %s", exploration)
            
            self.state = exploration.stashes["found"][0]
            self.log.info("Isolated synchronized state: %s", self.state)

        except ImportError as e:
            self.log.warning(e)
            self.log.info("Tip: Unlock symbolic execution functionality with `pip3 install %s[angr]`", self.log.name)

        except Exception as e:
            self.log.error("Must provide file backing process: %s", e)
            print("Usage: simulate <file>")
