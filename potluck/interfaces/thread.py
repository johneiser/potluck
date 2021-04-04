from . import Interface
from .process import ProcessInterface
from ..agent import Task
from .. import log
import queue, pprint


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

    @property
    def context(self):
        return self.hook.get("context")

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

    def do_capture(self, line):
        """capture
        capture the execution state for simulation"""
        try:
            import angr, archinfo
            from angr_targets import FridaConcreteTarget
            from io import BytesIO

            platform = self.agent.exports.get_platform()
            arch = self.agent.exports.get_arch()
            self.log.debug("Creating empty angr project for (platform, arch): %s, %s", platform, arch)

            # Create empty project
            p = angr.Project(BytesIO(b"\xCC"), #"/bin/nc.openbsd", # BytesIO(b"\xCC"),
                concrete_target = FridaConcreteTarget(self.agent, self.context),
                #use_sim_procedures=True,
                support_selfmodifying_code=True,
                #simos = platform,
                main_opts={
                    "backend": "blob",
                    "arch": arch, # archinfo.arch_from_id(arch, "lit"),
                    "entry_point": 0,
                    "base_addr": 0,
                })

            # Patch simos to match platform
            p.simos.get_segment_register_name = lambda: angr.simos.os_mapping[platform].get_segment_register_name(p.simos)

            self.log.debug("Created empty angr project: %s", p)

            # Create empty state
            self.log.debug("Creating empty angr state...")
            state = p.factory.blank_state()
            #state = p.factory.entry_state()
            #state.options.add(angr.options.SYMBION_SYNC_CLE)
            #state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
            self.log.debug("Created empty angr state: %s", state)

            # Sync state with concrete target
            self.log.debug("Syncing state with concrete target...")
            simgr = p.factory.simgr(state)
            simgr.use_technique(angr.exploration_techniques.Symbion(find=[int(self.context["pc"], 16)]))
            exploration = simgr.run()
            self.log.debug("Sync complete: %s", exploration)

            # Extract and store synchronized state
            self.state = exploration.stashes["found"][0]
            self.log.info("State captured: %s", self.state)

            #test = p.factory.simgr(self.state.copy())
            #print(test.active)
            #while (len(test.active) == 1):
            #    test.step()
            #    if test.active:
            #        print(test.active)
            #    else:
            #        print(test.errored)
            #        # State errored with "bytes can only be stored big-endian"
            #        # -> SimMemoryObject bug, patched below
            #pprint.pprint(test._stashes)

        except ImportError as e:
            self.log.warning(e)

try:
    import angr

    # Remove angr's default log handler
    for handler in log.parent.handlers:
        if isinstance(handler, angr.misc.loggers.CuteHandler):
            log.parent.removeHandler(handler)
            log.info("Removed default angr log handler: %s", handler)

    # Patch angr.storage.memory_object.SimMemoryObject bug
    from angr.storage.memory_object import SimMemoryObject
    init = SimMemoryObject.__init__
    def __init__(self, obj, base, endness, length=None, byte_width=8):
        if type(obj) == bytes and endness != "Iend_BE":
            obj = obj[::-1]
            endness = "Iend_BE"
        init(self, obj, base, endness, length, byte_width)
    setattr(SimMemoryObject, "__init__", __init__)
    log.info("Patched angr SimMemoryObject bug")

    class SimulatedThreadInterface(ThreadInterface):
        """
        Interface that supports being attached to a hooked thread
        while enjoying a fully simulated replica of the target
        process state.
        """
        state   = None  # Simulated execution state
        
        @property
        def prompt(self):
            return "[%s ~> %i]> " % (self.session, self.thread)

        @classmethod
        def _qualify(cls, self):
            ThreadInterface._qualify(self)
            assert hasattr(self, "state") and self.state is not None
            return cls

        def _exit(self):
            super(SimulatedThreadInterface, self)._exit()

            try:
                pass

            # Disqualify interface
            finally:
                self.state = None

except ImportError:
    #log.debug("Tip: use `pip3 install frida-potluck[angr]` to enable symbolic execution")
    pass
