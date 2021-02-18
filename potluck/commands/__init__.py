__all__ = []

# Automatically locate and import commands
import os, string
for root, dirs, files in os.walk(os.path.dirname(__file__)):
    for file in files:
        name,_,ext = file.partition(os.path.extsep)
        if ext == "py" and name[0] in string.ascii_letters:
            __all__.append(name)

from ..interfaces import interfaces
from fnmatch import fnmatch

def command(*names):
    """Decorator registering function with desired interfaces"""
    def decorate(func):
        for i in interfaces:
            for name in names:
                if fnmatch(i.__name__.lower(), name.lower()):
                    setattr(i, func.__name__, func)
        return func
    return decorate

