from .thread import ThreadInterface
from ..utils import parse_as, parse_line_as


class AngrInterface(ThreadInterface):
    """
    Interface that supports symbolic execution backed
    by a concrete target in a hooked thread.
    """
    bridge      = None  # Concrete target simulation bridge
    _state      = None  # Simulated execution state
    _image      = None  # Base image file path

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

    @property
    def image(self):
        """Lazy image only captured when needed"""
        if not self._image:
            self._image = self.agent.exports.get_image()
        return self._image

    @image.setter
    def image(self, value):
        """Enable override of default image"""
        self._image = value

        # Discard state
        self._state = None

    def do_image(self, line):
        """image
        get or set the base image file path"""

        (image,) = parse_line_as(line, [str])

        # Override default with custom image file path
        if image:
            self.image = image

        # Print current image file path
        print(self.image)

    def do_test(self, line):
        print(self.state)
