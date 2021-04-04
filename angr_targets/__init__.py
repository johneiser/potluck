from .concrete import ConcreteTarget

try:
    from .targets.frida_target import FridaConcreteTarget
except ImportError as e:
    pass
