import lib
class H:
    def __enter__(self):
        return lib.vulnerable()
    def __exit__(self,*a): return False
with H():
    pass
