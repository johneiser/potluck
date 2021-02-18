__all__ = [
    "base",
    "process",
    "thread",
    ]
import cmd, threading, queue, pprint
from .. import log

# Global registry of command prompt interfaces
interfaces = []


class Interfaceable(type):
    """
    Metaclass enabling interfaces to automatically register
    themselves for consideration.
    """

    def __init__(cls, name, bases, namespace):
        super(Interfaceable, cls).__init__(name, bases, namespace)

        # Register interface
        if hasattr(cls, "_qualify"):
            interfaces.append(cls)


class Interface(cmd.Cmd, metaclass=Interfaceable):
    """
    Command prompt capable of adapting to various conditions.

    Those who inherit Interface can implement the following functions:
    - _qualify: Assert whether interface is appropriate for environment
    - _exit: Perform any cleanup prior to leaving interface
    - _interrupt: Perform any action upon receiving a keyboard interrupt
    - _log_received: Subscribe to logs from an injected agent
    - _message_received: Subscribe to messages from an injected agent
    """
    event   = None  # Blocking event lock to hold prompt open
    queue   = None  # Message queue to synchronize hooks across threads
    script  = None  # List of automated commands to run for each hook
    log     = log   # Default to global log

    def __init__(self, *args, **kwargs):
        super(Interface, self).__init__(*args, **kwargs)

        # Initialize event lock
        self.event = threading.Event()
        self.event.set()

        # Initialize message queue
        self.queue = queue.Queue()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        
        # Handle interrupts
        if exc_type in (KeyboardInterrupt,
                        EOFError):
            if hasattr(self, "_interrupt"):
                self._interrupt()
                self._adapt()
            print("\r")
            return True

        # Handle known errors
        if exc_type in (ValueError,):
            self.log.error(exc_value)
            return True

        # Perform iterative cleanup
        while hasattr(self, "_exit"):
            self._exit()
            if not self._adapt():
                break

        # Exit cleanly
        if exc_type is None:
            raise KeyboardInterrupt()

        # Exit with exception
        return False

    def _adapt(self):
        """Adapt the interface according to the environment"""
        original = self.__class__

        # Cycle through all registered interfaces
        for interface in interfaces:

            # Apply class if qualified
            try:
                cls = interface._qualify(self)
                if cls and cls is not self.__class__ and issubclass(cls, Interface):
                    self.__class__ = cls
            except AssertionError:
                continue

        # Retrun True if class changed
        return self.__class__ is not original

    def emptyline(self):
        """Called when no command was entered"""
        # Do nothing (override default behavior)
        return False

    def preloop(self):
        """Called before the command loop starts"""

        # Wait for an event, if necessary
        timeout = not self.event.wait()

        # Adapt to the new environment
        self._adapt()

    def precmd(self, line):
        """Called before every command is executed"""
        return line

    def postcmd(self, stop, line):
        """Called after evey command is executed"""

        # Wait for an event, if necessary
        timeout = not self.event.wait()

        # Adapt to the new environment
        self._adapt()

        return stop or timeout

    def do_exit(self, line):
        """exit

        cleanup and quit"""

        # Each interface includes cleanup in _exit
        return True
