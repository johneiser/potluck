from .thread import ThreadInterface


class AngrInterface(ThreadInterface):
    """
    Interface that supports symbolic execution backed
    by a concrete target in a hooked thread.
    """
    state       = None  # Simulated execution state

    @classmethod
    def qualify(cls, self):
        """Evaluate the environment for this interface"""
        assert hasattr(self, "state") and self.state is not None
        return cls

    def _exit(self):
        """Called when exiting the prompt"""
        super(AngrInterface, self)._exit()

        # Dispose of state
        try:
            pass

        # Disqualify interface
        finally:
            self.state = None
