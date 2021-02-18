import shlex, frida, pprint, json
from . import Interface
from ..utils import parse_line_as, int16
from ..agent import source as agent


class BaseInterface(Interface):
    """
    Command prompt capable of attaching to a process and
    injecting an agent.
    """
    device  = None  # Device controlling the target process

    @classmethod
    def _qualify(cls, self):
        assert hasattr(self, "device") and self.device is not None
        return cls

    def _exit(self):

        # Disqualify device
        self.device = None

    @property
    def prompt(self):
        return "[%s]> " % self.device.name

    def __log_received(self, level, text):
        """Handle logs from an injected agent"""

        # Convert agent log to logging log
        func = getattr(self.log, level, self.log.info)
        func(text)

        # Notify consumers
        if hasattr(self, "_log_received"):
            self._log_received(level, text)

    def __message_received(self, message, data):
        """Handle messages from an injected agent"""
        self.log.debug("Received message: %s", message)

        # Parse message for payload
        try:
            payload = json.loads(message["payload"])

            # Notify consumers
            if hasattr(self, "_message_received"):
                self._message_received(payload, data)

        # Parse error messages
        except (json.decoder.JSONDecodeError, KeyError) as e:
            self.log.debug("Failed to process message: %s", e)
            pprint.pprint(message.get("description", message))

    def _attach(self, process):
        """
        Attach to the specified process.

        :param str process: Process name or id
        :raises: frida.ProcessNotFoundError
        """

        # Attach to process
        self.log.debug("Attaching to process: %s", process)
        self.session = self.device.attach(process)

        # Create agent
        self.agent = self.session.create_script(agent)
        self.log.debug("Injecting agent: %s", self.agent)

        # Subscribe to agent messages
        self.agent.on("message", self.__message_received)
        self.agent.set_log_handler(self.__log_received)

        # Load agent into process
        self.agent.load()

    def do_attach(self, line):
        """attach <process>
        attach to a process"""

        (process,) = parse_line_as(line, [int, str])

        try:
            self._attach(process)

        except (frida.ProcessNotFoundError,) as e:
            self.log.error(e)

    def do_spawn(self, line):
        """spawn <command>
        spawn a process and attach to it"""

        # Spawn process
        try:
            self.log.debug("Spawning process: %s", line)
            self.process = self.device.spawn(shlex.split(line))
            self.suspended = True

            # Attach to spawned process
            self._attach(self.process)

        except (frida.ExecutableNotFoundError,
                frida.PermissionDeniedError) as e:
            self.log.error(e)

        except Exception:

            # Kill process if exists
            if hasattr(self, "process") and self.process:
                self.device.kill(self.process)

            raise

