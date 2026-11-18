import importlib
m = importlib.import_module('.core', __package__)
m.vulnerable()
