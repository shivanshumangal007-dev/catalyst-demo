from importlib.metadata import entry_points
for ep in entry_points().select(group='x'):
    ep.load()()
