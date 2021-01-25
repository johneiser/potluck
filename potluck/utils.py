import pprint, logging
try:
    from prettytable import PrettyTable
except ImportError:
    pass

log = logging.getLogger(__package__)
log.setLevel(logging.DEBUG)


def tformat(items, **kwargs):
    """
    Format a list of arbitrary dictionary items as
    a pretty table.

    :param list items: items to include in table
    :return: table
    :rtype: str
    """
    try:
        if items:
            # Normalize input
            if not isinstance(items, list):
                items = [items]

            # Configure table
            t = PrettyTable(kwargs.get("field_names", items[0].keys()))
            for name, value in kwargs.items():
                setattr(t, name, value)

            # Add items to table
            for item in items:
                t.add_row([item.get(k) for k in t.field_names])

            return str(t)

    # Default to pprint if prettytable is not available
    except NameError:
        log.info("Tip: `pip3 install %s[pretty]` to improve this output", __package__)
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
    Format binary data to send to the agent.

    :param bytes data: data to send
    :return: compatible hex string
    :rtype: str
    """
    _ord = ord if isinstance(data, str) else int
    return " ".join(["%.2x" % _ord(b) for b in data])
