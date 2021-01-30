__all__ = [
    "test",
    "vulns",
    ]

simulations = {}

def simulation(sim):
    simulations[sim.__name__.lower()] = sim
    return sim
