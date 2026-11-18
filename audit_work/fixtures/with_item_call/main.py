import lib
class C:
    def __enter__(self): return self
    def __exit__(self,*a): return False
with C():
    pass
