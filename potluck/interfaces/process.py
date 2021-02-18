import frida
from . import Interface
from .base import BaseInterface
from ..utils import parse_line_as, int16
from ..agent import get_functions
from ..constants import DEFAULT_NUMBER_ARGUMENTS


class ProcessInterface(Interface):
    """
    Interface that supports being attached to a process.
    """
    session = None  # Session with the attached process
    agent   = None  # Agent injected into the attached process

    @property
    def prompt(self):
        return "[%s]> " % self.session

    @classmethod
    def _qualify(cls, self):
        BaseInterface._qualify(self)
        assert hasattr(self, "session") and self.session is not None
        assert hasattr(self, "agent") and self.agent is not None
        return cls

    def _exit(self):
        try:
            # Unload agent
            self.log.debug("Unloading agent: %s", self.agent)
            self.agent.unload()

            # Detach from session
            self.log.debug("Detaching from session: %s", self.session)
            self.session.detach()

        except (frida.InvalidOperationError,) as e:
            self.log.warning(e)

        # Disqualify interface
        finally:
            self.session = None
            self.agent = None

    def _interrupt(self):

        # Remove all hooks
        self.agent.exports.unhook()

        # Remove automated script
        if self.script:
            self.script = None

        # Resume prompt
        self.event.set()

    def _message_received(self, message, data):
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
                self.log.info(" @ %s %s!%s (%s) = %s" % (
                    func["address"], func["moduleName"], func["name"], ", ".join(args), ret))

                # Reset script
                if self.script:
                    self.cmdqueue = [c for c in self.script]

                # TODO: Dump memory state into angr

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
        (function, module, number) = parse_line_as(line,
            [int16, str], [str], [int, DEFAULT_NUMBER_ARGUMENTS])

        # Validate required arguments
        if not function:
            self.do_help("hook")
            return

        # Fetch functions
        functions = get_functions(self.agent, function, module)

        # Hook specified functions
        if functions:
            for function in functions:
                self.agent.exports.hook(function["address"], number)

            # Wait for hook
            self.event.clear()


class SpawnedProcessInterface(ProcessInterface):
    """
    Interface that supports being attached to a spawned process.
    """
    process = None  # Spawned process

    @classmethod
    def _qualify(cls, self):
        super(SpawnedProcessInterface, cls)._qualify(self)
        assert hasattr(self, "process") and self.process is not None
        return cls

    def _exit(self):
        super(SpawnedProcessInterface, self)._exit()
        
        # Kill spawned process..
        try:
            self.log.debug("Killing process: %s", self.process)
            self.device.kill(self.process)

        # .. if it still exists
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
    suspended   = None  # Whether process is suspended

    @property
    def prompt(self):
        return "[%s => %i]> " % (self.session, self.session._impl.pid)
    
    @classmethod
    def _qualify(cls, self):
        super(SuspendedProcessInterface, cls)._qualify(self)
        assert hasattr(self, "suspended") and self.suspended
        return cls

    def _exit(self):
        super(SuspendedProcessInterface, self)._exit()

        # Disqualify interface
        self.suspended = None
    
    def do_hook(self, line):
        """hook <function> [module] [number]
        hook the specified function(s) with number of arguments to parse"""

        # Parse arguments
        (function, module, number) = parse_line_as(line,
            [int16, str], [str], [int, DEFAULT_NUMBER_ARGUMENTS])

        # Validate required arguments
        if not function:
            self.do_help("hook")
            return

        # Fetch functions
        functions = get_functions(self.agent, function, module)

        # Hook specified functions
        if functions:
            for function in functions:
                self.agent.exports.hook(function["address"], number)

            # Continue execution
            self.device.resume(self.process)
            self.suspended = False

            # Wait for hook
            self.event.clear()

    def do_continue(self, line):
        """continue
        resume suspended process"""
        self.device.resume(self.process)
        self.suspended = False
