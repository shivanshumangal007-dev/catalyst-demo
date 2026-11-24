import importlib.metadata
for ep in importlib.metadata.entry_points().select(group='x'):
    ep.load()()
