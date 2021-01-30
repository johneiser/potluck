from . import simulation
from ..utils import log


# From https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/automated-exploit-development/buffer-overflows
def check_mem_corruption(simgr):
    log.info("Step: %s", simgr)
    if len(simgr.unconstrained):
        for path in simgr.unconstrained:
            if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCC"]):
                path.add_constraints(path.regs.pc == b"CCCC")
                if path.satisfiable():
                    simgr.stashes["mem_corrupt"].append(path)
                simgr.stashes["unconstrained"].remove(path)
                simgr.drop(stash="active")
    return simgr

#@simulation
def fuzz_pc(state, args, ret, *opts):
    """Check for corruption of the position counter"""

    simgr = state.project.factory.simulation_manager(state, save_unconstrained=True)
    simgr.stashes["mem_corrupt"] = []
    simgr.explore(step_func=check_mem_corruption)
   
    import pprint
    results = dict(simgr.stashes)
    results.update({"errored": simgr.errored})
    log.info("Results: %s", pprint.pformat(results))
    # State errored with "No bytes in memory for block starting at ..."
    #   (Waiting for https://github.com/angr/angr/issues/2384)
