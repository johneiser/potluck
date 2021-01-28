import angr
from . import simulation
from ..utils import log, int16


@simulation
def test(state, args, ret, *opts, **kwargs):
    log.info("Starting test simulation")
    log.debug(state)
    log.debug(args)
    log.debug(ret)

    # Print string behind every argument
    for arg in args:
        try:
            log.info(state.mem[int16(arg)].string.concrete)
        except angr.errors.SimConcreteMemoryError as e:
            log.warning(e.__cause__)
