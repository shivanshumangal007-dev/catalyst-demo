import lib

# In a real app this name comes from user configuration, making the target dynamic.
name = "vulnerable_function"
getattr(lib, name)()
