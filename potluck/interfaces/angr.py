from .thread import ThreadInterface
from ..utils import parse_as, parse_line_as


class AngrInterface(ThreadInterface):
    """
    Interface that supports symbolic execution backed
    by a concrete target in a hooked thread.
    """
    bridge      = None  # Concrete target simulation bridge
    _state      = None  # Simulated execution state

    @classmethod
    def qualify(cls, self):
        """Evaluate the environment for this interface"""
        super(AngrInterface, cls).qualify(self)
        assert hasattr(self, "bridge") and self.bridge is not None
        return cls

    @property
    def prompt(self):
        return "[%s ~> %i]> " % (self.session, self.thread)

    def _exit(self):
        """Called when exiting the prompt"""
        super(AngrInterface, self)._exit()

        # Dispose of state
        try:
            pass

        # Disqualify interface
        finally:
            self.bridge = None
            self._state = None

    @property
    def state(self):
        """Lazy state only captured when needed"""
        if not self._state:
            try:
                self._state = self.bridge.capture_state(self.image)
            except FileNotFoundError as e:
                self.log.error(e)
                self.log.warning("Need local copy of base image to perform symbolic execution. Use `image [path]` to point at your local copy.")
        return self._state

    def do_continue(self, line):
        """continue
        resume the thread execution"""

        # Dispose of state
        self.bridge = None
        self._state = None

        return super(AngrInterface, self).do_continue(line)

    def do_test(self, line):
        print(self.state)
