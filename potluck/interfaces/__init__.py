__all__ = [
    "base",
    "process",
    "thread",
    "angr",
]

import sys, cmd, shlex, logging, threading, queue, json, pprint, frida
from ..utils import log

# Global registry of command prompt interfaces
interfaces = {}


class Interfaceable(type):
    """
    Metaclass enabling interfaces to automatically
    register themselves for consideration.
    """

    def __init__(cls, name, bases, namespace):
        super(Interfaceable, cls).__init__(name, bases, namespace)

        # Register interface
        if hasattr(cls, "qualify"):
            interfaces[name] = cls


class Interface(cmd.Cmd, metaclass=Interfaceable):
    """
    Command prompt capable of adapting to various conditions.
    """
    event   = None  # Blocking lock to hold prompt between events
    queue   = None  # Blocking queue to synchronize hooks across threads
    log     = log
    
    class Interrupt(KeyboardInterrupt):
        """
        Custom exception to communicate an exit signal.
        """

    def __init__(self, *args, **kwargs):
        super(Interface, self).__init__(*args, **kwargs)

        # Initialize wait lock
        self.event = threading.Event()
        self.event.set()

        # Initialize message queue
        self.queue   = queue.Queue()

    def __enter__(self):
        """Called when entering context manager"""
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        """Called when leaving context manager"""

        # Suppress interrupt and continue
        if exc_type in (KeyboardInterrupt, EOFError):
            if hasattr(self, "_interrupt"):
                self._interrupt()
                self._adapt()
            print("\r")
            return True

        # Warn frida and parsing errors, but continue
        if exc_type in (frida.core.RPCException, ValueError):
            self.log.error(exc_value)
            return True

        # Perform iterative cleanup
        while hasattr(self, "_exit"):
            self._exit()
            if not self._adapt():
                break
        
        # Exit cleanly
        if exc_type is None:
            raise self.Interrupt()
    
        # Exit without suppressing exception
        return False

    def _adapt(self):
        """Adapt the interface according to the environment"""
        original = self.__class__

        # Cycle through all registered interfaces in order
        for name, interface in interfaces.items():

            # Apply class if qualified
            try:
                cls = interface.qualify(self)
                if cls and cls is not self.__class__ and issubclass(cls, Interface):
                    self.__class__ = cls
            
            # Interface disqualified itself
            except AssertionError:
                continue

        # Return True if class changed
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
        """Called before every command will execute"""
        return line

    def postcmd(self, stop, line):
        """Called after every command is finished executing"""

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

