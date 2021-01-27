import shlex, json, frida
from .agent import AgentInterface
from ..utils import tformat, tprint, parse_as, parse_line_as, int16

# Frontload importing angr, it's quite slow
try:
    from .angr_target import FridaConcreteTarget
except ImportError:
    pass

class ProcessInterface(AgentInterface):
    """
    Interface that supports being attached to a process.
    """
    session     = None  # Session with the attached process
    agent       = None  # Agent injected into the attached process
    script      = None  # Script to run for each hook
    
    @classmethod
    def qualify(cls, self):
        """Evaluate the environment for this interface"""
        assert hasattr(self, "session") and self.session is not None
        assert hasattr(self, "agent") and self.agent is not None
        return cls
    
    def _exit(self):
        """Called when exiting the prompt"""

        try:
            # Unload agent
            if hasattr(self, "agent") and self.agent:
                self.log.debug("Unloading agent: %s", self.agent)
                self.agent.unload()

            # Detach from process
            if hasattr(self, "session") and self.session:
                self.log.debug("Detaching from session: %s", self.session)
                self.session.detach()

        # Disqualify interface
        finally:
            self.session = None
            self.agent = None

    def _interrupt(self):
        """Called when the prompt is interrupted"""

        # Remove all hooks
        self.agent.exports.unhook()

        # Remove automated script, if set
        if self.script:
            self.script = None

        # Resume prompt
        self.event.set()

    @property
    def prompt(self):
        return "[%s]> " % self.session

    def callback(self, message, data):
        """Called when a message is received from the agent"""
        try:

            # Check if message is blocking
            if message.get("thread", None):

                # Switch to thread interface
                self.hook = message
                self._adapt()
            
                # Parse and log hook
                func = message["func"]
                args = message["args"]
                ret  = message["ret"]
                self.log.info("%s %s!%s (%s) = %s" % (
                    func["address"], func["moduleName"], func["name"], ", ".join(args), ret))

                # Reset script
                if self.script:
                    self.cmdqueue = [c for c in self.script]

                # Construct angr bridge
                try:
                    from .angr_target import FridaConcreteTarget
                    self.bridge = FridaConcreteTarget(self.agent, message["context"])
                except ImportError as e:
                    self.log.info("Tip: use `pip3 install %s[angr]` to enable symbolic execution", self.log.name)

                # Resume prompt
                self.event.set()

        except KeyError as e:
            self.log.warning("Failed to process message, missing key: %s", e)

    def do_detach(self, line):
        """detach
        detach from process"""
        self._exit()

    def do_hook(self, line):
        """hook <function> [module] [number]
        hook the specified function(s) with number of arguments to parse"""

        # Parse arguments
        (function, module, number) = parse_line_as(line, [int16, str], [str], [int, 3])

        # Validate required arguments
        if not function:
            print("Usage: hook <function> [module] [number]")
            return

        # Fetch modules and functions
        modules = self.get_modules(module)
        functions = self.get_functions(function)

        if functions:
            for function in functions:
                
                # Match functions to modules
                if module:
                    mod = self.agent.exports.get_module_by_address(function["address"])
                    if not mod or mod not in modules:
                        continue

                # Hook specified functions
                self.agent.exports.hook(function["address"], number)

            # Wait for hook
            self.event.clear()


class SpawnedProcessInterface(ProcessInterface):
    """
    Interface that supports being attached to a spawned process.
    """
    process     = None      # Spawned process

    @classmethod
    def qualify(cls, self):
        """Evaluate the environment for this interface"""
        super(SpawnedProcessInterface, cls).qualify(self)
        assert hasattr(self, "process") and self.process is not None
        return cls

    def _exit(self):
        """Called when exiting the prompt (must disqualify)"""
        super(SpawnedProcessInterface, self)._exit()

        # Kill spawned process..
        try:
            self.log.debug("Killing process: %s", self.process)
            self.device.kill(self.process)

        # ..if it still exists
        except (frida.ProcessNotFoundError,) as e:
            self.log.debug(e)

        # Disqualify interface
        finally:
            self.process = None
    

class SuspendedProcessInterface(SpawnedProcessInterface):
    """
    Interface that supports being attached to a spawned process
    that is still in a suspended state.
    """
    suspended   = None      # Whether process is suspended

    @classmethod
    def qualify(cls, self):
        """Evaluate the environment for this interface"""
        super(SuspendedProcessInterface, cls).qualify(self)
        assert hasattr(self, "suspended") and self.suspended
        return cls

    @property
    def prompt(self):
        return "[%s => %i]> " % (self.session, self.session._impl.pid)

    def do_continue(self, line):
        """continue
        resume suspended process"""
        self.device.resume(self.process)
        self.suspended = False

    def do_hook(self, line):
        """hook <function> [module] [number]
        hook the specified function(s) with number of arguments to parse"""
        super(SpawnedProcessInterface, self).do_hook(line)
        
        # Continue after settings hooks
        self.device.resume(self.process)
        self.suspended = False
        
