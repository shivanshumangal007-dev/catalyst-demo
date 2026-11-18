import lib, threading
t = threading.Thread(target=lib.vulnerable)
t.start()
t.join()
