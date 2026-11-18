import lib, functools
f = functools.partial(lib.vulnerable)
f()
