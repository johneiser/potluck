from angr.errors import SimConcreteMemoryError, SimConcreteRegisterError, SimConcreteBreakpointError
from ..concrete import ConcreteTarget
from ..memory_map import MemoryMap
import logging, frida 

log = logging.getLogger("potluck")


class FridaConcreteTarget(ConcreteTarget):
    """
    Concrete target to provide state for symbolic execution via frida.
    """
    agent       = None  # Agent injected into the attached process
    context     = None  # CPU context at the hooked location

    def __init__(self, agent, context):
        super(FridaConcreteTarget, self).__init__()
        self.agent = agent
        self.context = context

    def read_memory(self, address, nbytes, **kwargs):
        """
        Reading from memory of the target.

        :param int address: the address to read from
        :param int nbytes: the number of bytes to read
        :return: the memory read
        :rtype: bytes
        :raise: angr.errors.SimConcreteMemoryError
        """
        try:
            log.debug("[TEST] read_memory %s %i", address, nbytes)
            return self.agent.exports.read("0x%x" % address, nbytes)
        
        except frida.core.RPCException as e:
            raise SimConcreteMemoryError from e

    def write_memory(self, address, value, **kwargs):
        """
        Writing to memory of the target.

        :param int address: the address from where teh memory-write should start
        :param bytes value: the actual value written to memory
        :raise: angr.errors.SimConcreteMemoryError
        """
        try:
            log.debug("[TEST] write_memory %s %s", address, value)
        
        except frida.core.RPCException as e:
            raise SimConcreteMemoryError from e
        
        raise NotImplementedError()

    def read_register(self, register, **kwargs):
        """
        Read a register from the target.

        :param str register: the name of the register
        :return: register content
        :rtype: int
        :raise: angr.errors.SimConcreteRegisterError
        """
        try:
            log.debug("[TEST] read_register %s", register)
            return int(self.context[register], 16)
        
        except (KeyError, ValueError) as e:
            raise SimConcreteRegisterError from e
        
    def write_register(self, register, value, **kwargs):
        """
        Write to register of the target.

        :param str register: the name of the register
        :param int value: value to be written to the register
        :raise: angr.errors.SimConcreteRegisterError
        """
        log.debug("[TEST] write_register %s", register)
        raise NotImplementedError()

    def read_all_registers(self):
        """
        Read the entire register file from the target.

        :return: dictionary mapping of register str to int value
        :rtype: dict
        :raise: angr.errors.SimConcreteRegisterError
        """
        log.debug("[TEST] read_all_registers")
        raise NotImplementedError()

    def write_all_registers(self, values):
        """
        Write the entire register file to the target.

        :param dict values: dictionary mapping of register str to int value
        :raise: angr.errors.SimConcreteRegisterError
        """
        log.debug("[TEST] write_all_registers")
        raise NotImplementedError()

    def set_breakpoint(self, address, **kwargs):
        """
        Insert a breakpoint.

        :param int address: the address of the breakpoint
        :param optional bool hardward: hardware breakpoint
        :param optional bool temporary: temporary breakpoint
        :raise: angr.errors.SimConcreteBreakpointError
        """
        log.debug("[TEST] set_breakpoint %s", address)

        # Ignoring, already at destination
        return

    def remove_breakpoint(self, address, **kwargs):
        """
        Remove a breakpoint.

        :param int address: the address of the breakponit
        :raise: angr.errors.SimConcreteBreakpointError
        """
        log.debug("[TEST] remove_breakpoint %s", address)
        
        # Ignoring, already at destination
        return

    def set_watchpoint(self, address, **kwargs):
        """
        Insert a watchpoint.

        :param int address: the address of the watchpoint
        :param optional bool write: write watchpoint
        :param optional bool read: read watchpoint
        :raise: angr.errors.SimConcreteBreakpointError
        """
        try:
            log.debug("[TEST] set_watchpoint %s", address)
        except frida.core.RPCException as e:
            raise SimConcreteBreakpointError from e
        
        raise NotImplementedError()

    def remove_watchpoint(self, address, **kwargs):
        """
        Remove a watchpoint.

        :param int address: the address of the watchpoint
        :raise: angr.errors.SimConcreteBreakpointError
        """
        try:
            log.debug("[TEST] remove_watchpoint %s", address)
        except frida.core.RPCException as e:
            raise SimConcreteBreakpointError from e

        raise NotImplementedError()

    def get_mappings(self):
        """
        Get the memory mappings of the target process.

        :return: mappings
        :rtype: list
        """
        log.debug("[TEST] get_mappings")
        
        mappings = []
        for m in self.agent.exports.get_ranges():
            mappings.append(MemoryMap(
                int(m["base"], 16),
                int(m["base"], 16) + int(m["size"]),
                int(m["file"]["offset"]) if m.get("file") else 0,
                m["file"]["path"] if m.get("file") else "<anonymous",
                ))
        return mappings

    def run(self):
        log.debug("[TEST] run")

        # Ignore, already at destination
        return

    def is_running(self):
        log.debug("[TEST] is_running")
        return False

    def step(self):
        log.debug("[TEST] step")
        raise NotImplementedError()

    def stop(self):
        log.debug("[TEST] stop")
        raise NotImplementedError()

    def reset(self, halt=False):
        log.debug("[TEST] reset")
        raise NotImplementedError()

    def wait_for_running(self):
        log.debug("[TEST] wait_for_running")
        raise NotImplementedError()

    def wait_for_halt(self):
        log.debug("[TEST] wait_for_halt")
        raise NotImplementedError()

    def wait_for_breakpoint(self, which=None):
        """
        
        :param int which: address of the breakpoint to wait for
        """
        log.debug("[TEST] wait_for_breakpoint")
        raise NotImplementedError()

    def exit(self):
        log.debug("[TEST] exit")
        raise NotImplementedError()

    @property
    def architecture(self):
        log.debug("[TEST] architecture")
        return self.agent.exports.get_arch()

    @property
    def bits(self):
        log.debug("[TEST] bits")
        return int(self.agent.exports.get_pointer_size()) * 8

