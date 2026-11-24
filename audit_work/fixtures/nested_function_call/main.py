import lib
def outer():
    def inner():
        lib.vulnerable()
    inner()
outer()
