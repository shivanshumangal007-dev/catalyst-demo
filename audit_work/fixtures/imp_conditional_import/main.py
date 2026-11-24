try:
    from pkg.core import vulnerable as v
except ImportError:
    v = None
v()
