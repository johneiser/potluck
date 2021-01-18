import logging, threading, cmd, json, pprint 

log = logging.getLogger(__package__)


def to_hex(data):
    """
    Format binary data to send to agent.

    :param bytes data: data to send to agent
    :return: compatible hex string
    :rtype: str
    """
    _ord = ord if isinstance(data, str) else int
    return " ".join(["%x" % _ord(_) for _ in data])


class Task:
    """
    Define a task that the agent should perform during
    a hook interrupt.
    """
    NOP     = 0
    RESUME  = 1
    READ    = 2     # { addr, size }

    type    = 0
    args    = None

    def __init__(self, type=0, args=None):
        self.type = type
        self.args = args


class Message:
    """
    Define a message that can be sent to the agent
    during a hook interrupt to perform a number of
    tasks.
    """
    type    = None
    payload = None

    def __init__(self, thread, tasks=None):
        self.type = thread
        self.payload = tasks or []


class Prompt(cmd.Cmd):
    """
    Define a command prompt capable of interacting
    with the injected agent.
    """
    session     = None
    agent       = None
    hook        = None
    event       = None

    def __init__(self, session, agent, *args, **kwargs):
        super(Prompt, self).__init__(*args, **kwargs)
        self.session = session
        self.agent = agent
        self.event = threading.Event()
       
    @property
    def prompt(self):
        if self.hook and "thread" in self.hook:
            return "[%s => %i]> " % (self.session, self.hook["thread"])
        return "[%s]> " % self.session

    def emptyline(self):
        return False

    def preloop(self):
        self.event.wait()

    def postcmd(self, stop, line):
        return stop or not self.event.wait()

    def callback(self, message, data):
        log.debug("Received message: %s", message)

        # Parse message payload
        try:
            self.hook = json.loads(message["payload"])
            func = self.hook["func"]
            args = self.hook["args"]
            ret = self.hook["retval"]

            # Print backtrace
            print()
            offset = 0
            for addr in self.hook["backtrace"][::-1]:
                print(" "*offset + addr)
                offset += 1
            
            # Print function call
            print(" "*offset + "%s %s!%s (%s) = %s" % (
                func["address"], func["moduleName"], func["name"], ", ".join(args), ret))
            print()

            # Open command prompt
            self.event.set()

        except (json.decoder.JSONDecodeError, KeyError) as e:
            log.debug("Failed to process message: %s", e)
            pprint.pprint(message.get("description"))

