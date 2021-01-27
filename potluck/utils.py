import pprint, logging, shlex
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
        log.info("Tip: use `pip3 install %s[pretty]` to improve this output", __package__)
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

def int16(item):
    """
    Parse a string as a base 16 integer.

    :param str imt: item to parse
    :return: parsed item
    :rtype: int
    :raises: ValueError
    """
    return int(item, 16)

def parse_as(item, *types):
    """
    Parse an item according to a number of possible types.

    :param str item: item to parse
    :param callable *types: possible types
    :return: parsed item
    :rtype: object
    """
    for t in types:
        if callable(t):
            if item:
                try:
                    return t(item)
                except ValueError as e:
                    pass
        else:
            return t
    return None

def parse_line_as(line, *typelists):
    """
    Parse a line for a number of items.

    :param str line: line to parse
    :param list *typelists: list of types for each item
    :return: parsed items
    :rtype: generator
    #:raises: ValueError if no types match
    """
    items = shlex.split(line)
    for i,t in enumerate(typelists):
        try:
            yield parse_as(items[i], *t)
        except IndexError as e:
            yield parse_as(None, *t)
