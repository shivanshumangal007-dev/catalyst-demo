import lib

name = "vulnerable_function"  # comes from config in a real app
getattr(lib, name)()
