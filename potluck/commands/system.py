from . import command
from ..utils import tprint, parse_line_as
from fnmatch import fnmatch


@command("ProcessInterface", "ThreadInterface")
def do_system(self, line):
    """system
    get information about the target system"""
    print("%s %s" % (
        self.agent.exports.get_platform(),
        self.agent.exports.get_arch(),
        ))


@command("*")
def do_ps(self, line):
    """ps [name]
    list the current processes"""

    # Parse arguments
    (name,) = parse_line_as(line, [str, "*"])

    # Fetch process list
    processes = [{"pid" : p.pid, "name": p.name
        } for p in self.device.enumerate_processes() if fnmatch(p.name.lower(), name.lower())]

    # Print process list
    tprint(processes, sortby="pid", align="l", field_names=["pid", "name"])

