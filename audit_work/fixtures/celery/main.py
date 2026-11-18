import lib
class C:
    def task(self):
        return lib.vulnerable()
    def on_event(self):
        return lib.vulnerable()
task = C().task
on_event = C().on_event
