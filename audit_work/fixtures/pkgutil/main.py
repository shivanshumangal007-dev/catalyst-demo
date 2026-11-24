import pkgutil, importlib
for m in pkgutil.iter_modules():
    importlib.import_module(m.name)
