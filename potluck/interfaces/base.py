import shlex, json, pprint, frida
from . import Interface


class Prompt(Interface):
    """
    Command prompt capable of attaching to a process and
    injecting an agent.
    """
    device      = None  # Device controlling the target process
    source      = None  # Source code of agent to inject
    prompt      = "[_local_]> "

    def __init__(self, device, agent, *args, **kwargs):
        super(Prompt, self).__init__(*args, **kwargs)
        self.device = device
        self.source = agent

    @classmethod
    def qualify(cls, self):
        """Evaluate the environment for this interface"""
        return cls

    @property
    def prompt(self):
        return "[%s]> " % self.device.name

    def _log_handler(self, level, text):

        # Convert agent log to logging log
        func = getattr(self.log, level, pprint.pprint)
        func(text)
        
        # Notify consumers
        if hasattr(self, "log_handler"):
            self.log_handler(level, text)

    def _callback(self, message, data):
        self.log.debug("Received message: %s", message)

        # Parse message for payload
        try:
            payload = json.loads(message["payload"])

            # Notify consumers
            if hasattr(self, "callback"):
                self.callback(payload, data)

        # Parse error messages
        except (json.decoder.JSONDecodeError, KeyError) as e:
            self.log.debug("Failed to process message: %s", e)
            pprint.pprint(message.get("description", message))

    def do_spawn(self, command):
        """spawn <command>
        spawn a process and attach to it"""

        # Spawn process
        try:
            self.log.debug("Spawning process: %s", command)
            self.process = self.device.spawn(shlex.split(command))
            self.suspended = True

            # Attach to spawned process
            self.do_attach(self.process)

        except (frida.ExecutableNotFoundError, frida.PermissionDeniedError) as e:
            self.log.error(e)

        except Exception:

            # Kill process if exists
            if hasattr(self, "process") and self.process:
                self.device.kill(self.process)

            raise

    def do_attach(self, process):
        """attach <process>
        attach to a process"""

        # Check if process is a pid
        try:
            process = int(process)
        except ValueError:
            pass

        try:
            # Attach to process
            self.log.debug("Attaching to process: %s", process)
            self.session = self.device.attach(process)
            
            # Create agent
            self.agent = self.session.create_script(self.source)
            self.log.debug("Injecting agent: %s", self.agent)
            
            # Subscribe to agent messages
            self.agent.on("message", self._callback)
            self.agent.set_log_handler(self._log_handler)
            
            # Load agent into process
            self.agent.load()

        except (frida.ProcessNotFoundError,) as e:
            self.log.error(e)

        except Exception:
            
            # Detach and dispose of session
            if hasattr(self, "session") and self.session:
                self.log.debug("Detaching session: %s", self.session)
                self.session.detach()
            
            self.session = None
            self.agent = None

            raise

