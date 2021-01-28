__all__ = [
    "test",
    ]

simulations = {}

def simulation(sim):
    simulations[sim.__name__.lower()] = sim
    return sim
