import logging, threading, cmd, json, pprint 
try:
    from prettytable import PrettyTable
except ImportError:
    pass

log = logging.getLogger(__package__)


def tformat(items, **kwargs):
    """
    Format a list of arbitrary dictionary items as
    a pretty table.

    :param list items: items to include in table
    :return: table
    :rtype: str
    """
    try:
        if items is not None and len(items) > 0:
            
            # Configure table
            t = PrettyTable(kwargs.get("field_names", items[0].keys()))
            for name, value in kwargs.items():
                setattr(t, name, value)

            # Add items to table
            for item in items:
                t.add_row([item.get(_) for _ in t.field_names])
            
            return str(t)

    # Default to pprint if prettytable is not available
    except NameError:
        log.warning("Tip: `pip install prettytable` to improve this output")
        return pprint.pformat(items)

def tprint(*args, **kwargs):
    """
    Print out a list of arbitrary dictionary items
    as a pretty table.

    :param list items: items to include in table
    """
    print(tformat(*args, **kwargs))

def to_hex(data):
    """
    Format binary data to send to agent.

    :param bytes data: data to send to agent
    :return: compatible hex string
    :rtype: str
    """
    _ord = ord if isinstance(data, str) else int
    return " ".join(["%.2x" % _ord(_) for _ in data])


class Task:
    """
    Define a task that the agent should perform during
    a hook interrupt.
    """
    NOP     = 0
    RESUME  = 1
    CALL    = 2

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
    script      = None

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

            # Open command prompt and reset command queue
            self.cmdqueue = [i for i in self.__class__.script]
            self.event.set()

        except (json.decoder.JSONDecodeError, KeyError) as e:
            log.debug("Failed to process message: %s", e)
            pprint.pprint(message.get("description"))

