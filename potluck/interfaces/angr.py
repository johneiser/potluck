import shlex
from .thread import ThreadInterface
from ..utils import parse_as, parse_line_as, int16
from ..simulations import simulations

# Try to populate simulation list
try:
    from ..simulations import *
    import angr, claripy
except ImportError:
    pass

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

        # Capture current state
        if not self._state:
            try:
                self._state = self.bridge.capture_state(self.image)

            # Cancel whatever command asked for the state
            except FileNotFoundError as e:
                self.log.error(e)
                self.log.warning("Need local copy of base image to perform symbolic execution. Use `image [path]` to point at your local copy.")
                raise KeyboardInterrupt from e

        return self._state

    def do_continue(self, line):
        """continue
        resume the thread execution"""

        # Dispose of state
        self.bridge = None
        self._state = None

        return super(AngrInterface, self).do_continue(line)

    def do_simulate(self, line):
        """simulate <simulation> [options]
        run a simulation"""
        
        # Run simulation
        try:
            sim,_,opts = line.partition(" ")
            func = simulations[sim.lower()]
            func(self.state.copy(), self.args, self.ret, *shlex.split(opts))

        # Show available simulations
        except KeyError as e:
            print("Simulation not found: %s" % e)
            print("Usage: symrun <simulation> [options]")
            self.print_topics("Simulations available", list(simulations.keys()), 15, 80)

        # Handle unknown simulation errors
        except Exception as e:
            self.log.exception(e)

    def complete_simulate(self, text, line, begidx, endidx):
        """Complete command from available simulations"""
        if text:
            return [s for s in simulations.keys() if s.startswith(text.lower())]
        return simulations.keys()

    def do_symaddr(self, line):
        """simaddr <address> <size> [name]
        mark memory address as symbolic"""

        # Parse arguments
        (addr, size, name) = parse_line_as(line, [int, int16], [int, int16], [str, "addr"])

        # Validate required arguments
        if not addr or not size:
            print("Usage: simaddr <address> <size> [name]")
            return

        # Convert argument to address
        if isinstance(addr, int):
            try:
                addr = int16(self.args[addr])
            except IndexError:
                pass

        # Symbolize address     # TODO: cache symbols, enable removal/clear from state
        sym = claripy.BVS(name, size * 8)
        self.state.memory.store(addr, sym)
        self.log.info("Marked 0x%x with %i bytes of symbolic memory, named '%s'", addr, size, name)

