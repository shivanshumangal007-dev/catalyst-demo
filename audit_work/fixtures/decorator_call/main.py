import lib
def deco(f):
    lib.vulnerable()
    return f
@deco
def g():
    pass
g()
