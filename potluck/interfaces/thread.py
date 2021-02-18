from . import Interface
from .process import ProcessInterface
from ..agent import Task
from .. import log
import queue


class ThreadInterface(Interface):
    """
    Interface that supports being attached to a hooked thread.
    """
    hook    = None  # Context of current hook

    @property
    def prompt(self):
        return "[%s => %i]> " % (self.session, self.thread)

    @classmethod
    def _qualify(cls, self):
        ProcessInterface._qualify(self)
        assert hasattr(self, "hook") and self.hook is not None
        return cls

    def _exit(self):
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
                        "type": self.thread,
                        "payload": [
                            { "type" : Task.RESUME },
                        ]})

                    # Pull next hook
                    self.hook = self.queue.get(False)

            except queue.Empty:
                pass

        # Disqualify interface
        finally:
            self.hook = None

    def _message_received(self, message, data):

        # Check if message is blocking
        if message.get("thread", None):

            # Add hook to queue
            self.queue.put(message)

    @property
    def thread(self):
        return self.hook.get("thread", 0)

    def do_tid(self, line):
        """tid
        get the thread id of the current hook"""
        print(self.thread)

    def do_unhook(self, line):
        """unhook
        remove all hooks and resume thread"""
        self._exit()

    def do_continue(self, line):
        """continue
        resume thread"""

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

try:
    import angr

    # Remove angr's default log handler
    for handler in log.parent.handlers:
        if isinstance(handler, angr.misc.loggers.CuteHandler):
            log.parent.removeHandler(handler)
            log.debug("Removed default angr log handler: %s", handler)

    class SimulatedThreadInterface(ThreadInterface):
        """
        Interface that supports being attached to a hooked thread
        while enjoying a fully simulated replica of the target
        process state.
        """
        
        @property
        def prompt(self):
            return "[%s ~> %i]> " % (self.session, self.thread)

        @classmethod
        def _qualify(cls, self):
            ThreadInterface._qualify(self)
            return cls

        def _exit(self):
            super(SimulatedThreadInterface, self)._exit()

            try:
                pass

            # Disqualify interface
            finally:
                pass

except ImportError:
    # TODO: Implement angr
    #log.debug("Tip: use `pip3 install frida-potluck[angr]` to enable symbolic execution")
    pass
