import lib
def g():
    yield lib.vulnerable()
list(g())
