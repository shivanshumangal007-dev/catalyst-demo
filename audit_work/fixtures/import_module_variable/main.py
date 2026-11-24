import importlib
name = 'lib'
lib = importlib.import_module(name)
lib.vulnerable()
