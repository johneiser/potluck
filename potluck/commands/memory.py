from . import command
from ..utils import parse_line_as, int16
from ..agent import dump, search
from ..constants import DEFAULT_RECURSION_LIMIT, DEFAULT_DUMP_MEMORY_SIZE, DEFAULT_SEARCH_MEMORY_SIZE


@command("ProcessInterface")
def do_dump(self, line):
    """dump <address> [size] [limit]
    dump bytes from the specified address"""

    # Parse arguments
    (address, size, limit) = parse_line_as(line,
        [int16, str], [int, int16, DEFAULT_DUMP_MEMORY_SIZE], [int, 0])

    # Validate required arguments
    if not address:
        self.do_help("dump")
        return

    # Perform read
    dump(self.agent, address, size, limit)


@command("ProcessInterface")
def do_dumpr(self, line):
    """dump <address> [size]
    dump bytes recursively from the specified address"""

    # Parse arguments
    (address, size, limit) = parse_line_as(line,
        [int16, str], [int, int16, DEFAULT_DUMP_MEMORY_SIZE], [DEFAULT_RECURSION_LIMIT])

    # Validate required arguments
    if not address:
        self.do_help("dumpr")
        return

    # Perform read
    dump(self.agent, address, size, limit)

#
# Augment dump in thread interface to include argument specification
#

@command("ThreadInterface")
def do_dump(self, line):
    """dump [address|arg] [size] [limit]
    dump bytes from the specified address or argument"""
    
    # Parse arguments
    (address, size, limit) = parse_line_as(line,
        [int16, str], [int, int16, DEFAULT_DUMP_MEMORY_SIZE], [int, 0])

    # Try to dump all arguments as addresses
    if address is None:
        try:
            for arg in self.hook["args"]:
                dump(self.agent, int16(arg), size, limit)
        except (KeyError,):
            pass

    else:
        # Resolve argument to address
        if isinstance(address, int):
            try:
                address = int16(self.hook["args"][address])
            except (KeyError, IndexError):
                pass
    
        # Read specified address
        dump(self.agent, address, size, limit)


@command("ThreadInterface")
def do_dumpr(self, line):
    """dump [address|arg] [size]
    dump bytes recursively from the specified address or argument"""
    
    # Parse arguments
    (address, size, limit) = parse_line_as(line,
        [int16, str], [int, int16, DEFAULT_DUMP_MEMORY_SIZE], [DEFAULT_RECURSION_LIMIT])

    # Try to dump all arguments ass addresses
    if address is None:
        try:
            for arg in self.hook["args"]:
                dump(self.agent, int16(arg), size, limit)
        except (KeyError,):
            pass

    else:
        # Resolve argument to address
        if isinstance(address, int):
            try:
                address = int16(self.hook["args"][address])
            except (KeyError, IndexError):
                pass

        # Read specified address
        dump(self.agent, address, size, limit)


@command("ProcessInterface")
def do_search(self, line):
    """search <pattern> [address] [size] [limit]
    search for a byte pattern at the specified address"""

    # Parse arguments
    (pattern, address, size, limit) = parse_line_as(line,
        [str], [int16, str], [int, int16, DEFAULT_SEARCH_MEMORY_SIZE], [int, 0])

    # Validate required arguments
    if not pattern:
        self.do_help("search")
        return

    # Perform search
    search(self.agent, pattern, address, size, limit)
  

@command("ProcessInterface")
def do_searchr(self, line):
    """searchr <pattern> [address] [size]
    search recursively for a byte pattern at the specified address"""

    # Parse arguments
    (pattern, address, size, limit) = parse_line_as(line,
        [str], [int16, str], [int, int16, DEFAULT_SEARCH_MEMORY_SIZE], [DEFAULT_RECURSION_LIMIT])

    # Validate required arguments
    if not pattern:
        self.do_help("searchr")
        return

    # Perform search
    search(self.agent, pattern, address, size, limit if address else 0)
  
#
# Augment search in thread interface to include argument specification
#

@command("ThreadInterface")
def do_search(self, line):
    """search <pattern> [address|arg] [size] [limit]
    search for a byte pattern at the specified address or argument"""
    
    # Parse arguments
    (pattern, address, size, limit) = parse_line_as(line,
        [str], [int16, str], [int, int16, DEFAULT_SEARCH_MEMORY_SIZE], [int, 0])

    # Validate required arguments
    if not pattern:
        self.do_help("search")
        return

    if address is not None:
    
        # Resolve argument to address
        if isinstance(address, int):
            try:
                address = int16(self.hook["args"][address])
            except (KeyError, IndexError):
                pass

    # Search specified address
    search(self.agent, pattern, address, size, limit)


@command("ThreadInterface")
def do_searchr(self, line):
    """searchr <pattern> [address|arg] [size]
    search recursively for a byte pattern at the specified address or argument"""
    
    # Parse arguments
    (pattern, address, size, limit) = parse_line_as(line,
        [str], [int16, str], [int, int16, DEFAULT_SEARCH_MEMORY_SIZE], [DEFAULT_RECURSION_LIMIT])

    # Validate required arguments
    if not pattern:
        self.do_help("searchr")
        return

    if address is not None:
        
        # Resolve argument to address
        if isinstance(address, int):
            try:
                address = int16(self.hook["args"][address])
            except (KeyError, IndexError):
                pass

    # Search specified address
    search(self.agent, pattern, address, size, limit)
